"use strict";

const fetchConfig = {
    baseURL: window.location,
    mode: 'same-origin',
    headers: {'Accept': 'application/json'},
};
/*
// Useful for development of the embedded webserver files.
const fetchConfig = {
    baseURL: 'http://127.0.0.1:8083/',
    mode: 'cors',
    headers: {'Accept': 'application/json', 'X-API-Key': 'changeme'},
};
*/

var gdata = {};

function get_json(url, params) {
    const realURL = new URL(url, fetchConfig.baseURL);
    if (params) {
        for (const [k, v] of Object.entries(params)) {
            realURL.searchParams.append(k, v);
        }
    }
    return new Promise((resolve, reject) => {
        fetch(realURL, {
            method: 'GET',
            mode: fetchConfig.mode,
            cache: 'no-cache',
            headers: fetchConfig.headers,
        }).then((response) => {
            if (response.ok) {
                response.json().then((json) => resolve(json));
            } else {
                reject(`HTTP Status ${response.status} ${response.statusText}`);
            }
        }).catch((error) => {
            reject(error.message);
        })
    });
}

function startup() {
    var getTemplate = function (name) {
        const template = document.querySelector(`#${name}-template`).innerHTML;
        return Handlebars.compile(template);
    };
    var cachedTemplates = {};
    var render = function (name, ctx) {
        var t = cachedTemplates[name];
        if (!t) {
            t = getTemplate(name);
            cachedTemplates[name] = t;
        }
        const html = t(ctx);
        document.querySelector('#' + name).innerHTML = html;
    };

    var qpsgraph = new Rickshaw.Graph({
        element: document.getElementById("qpschart"),
        width: 400,
        height: 200,
        renderer: 'line',
        series: new Rickshaw.Series.FixedDuration([{name: 'servfailps'}, {name: 'qps'}], undefined, {
            timeInterval: 1000,
            maxDataPoints: 100,
            timeBase: new Date().getTime() / 1000
        })
    });
    var y_ticks = new Rickshaw.Graph.Axis.Y({
        graph: qpsgraph,
        orientation: 'left',
        tickFormat: Rickshaw.Fixtures.Number.formatKMBT,
        element: document.getElementById('qpsy_axis')
    });

    qpsgraph.render();

    var cpugraph = new Rickshaw.Graph({
        element: document.getElementById("cpuchart"),
        width: 400,
        height: 200,
        renderer: 'line',
        series: new Rickshaw.Series.FixedDuration([{name: 'one'}], undefined, {
            timeInterval: 1000,
            maxDataPoints: 100,
            timeBase: new Date().getTime() / 1000
        })
    });
    var cpu_y_ticks = new Rickshaw.Graph.Axis.Y({
        graph: cpugraph,
        orientation: 'left',
        tickFormat: Rickshaw.Fixtures.Number.formatKMBT,
        element: document.getElementById('cpuy_axis')
    });

    cpugraph.render();
    var intervalcount = 0;

    var jsonstatParams = function (command, name, filtered) {
        var d = {
            'command': command,
            'name': name
        };
        if (filtered) {
            d['public-filtered'] = '1';
        }
        return d;
    };

    var makeRingRows = function (data) {
        var num = 0;
        var total = 0, rest = 0;
        var rows = [];
        data["entries"].forEach((b) => {
            total += b[0];
            if (num++ > 10) {
                rest += b[0];
                return;
            }
            if (b[1].length > 25)
                b[1] = b[1].substring(0, 25);
            rows.push(b);
        });
        while (rows.length < 10) {
            rows.push([]);
        }
        rows.push([rest, 'REST', '']);
        return rows;
    };

    function updateRingBuffers() {
        const filterChecked = document.querySelector("#filter1").checked;
        get_json('jsonstat', jsonstatParams('get-query-ring', 'queries', filterChecked)).then(
            function (data) {
                var rows = makeRingRows(data);
                render('queryring', {rows: rows});
            });

        get_json('jsonstat', jsonstatParams('get-query-ring', 'servfail-queries', filterChecked)).then(
            function (data) {
                var rows = makeRingRows(data);
                render('servfailqueryring', {rows: rows});
            });

        get_json('jsonstat', jsonstatParams('get-query-ring', 'bogus-queries', filterChecked)).then(
            function (data) {
                var rows = makeRingRows(data);
                render('bogusqueryring', {rows: rows});
            });

        get_json('jsonstat', jsonstatParams('get-remote-ring', 'remotes', false)).then(
            function (data) {
                var rows = makeRingRows(data);
                render('remotering', {rows: rows});
            });

        get_json('jsonstat', jsonstatParams('get-remote-ring', 'servfail-remotes', false)).then(
            function (data) {
                var rows = makeRingRows(data);
                render('servfailremotering', {rows: rows});
            });

        get_json('jsonstat', jsonstatParams('get-remote-ring', 'bogus-remotes', false)).then(
            function (data) {
                var rows = makeRingRows(data);
                render('bogusremotering', {rows: rows});
            });
        get_json('jsonstat', jsonstatParams('get-remote-ring', 'timeouts', false)).then(
            function (data) {
                var rows = makeRingRows(data);
                render('timeouts', {rows: rows});
            });
    }

    var connectionOK = function (ok, reason) {
        if (ok) {
            document.querySelector("#connection-status").style.display = "none";
            document.querySelector("#connection-error").innerHTML = "";
            document.querySelector("#content-hidden-on-load").style.display = "inherit";
        } else {
            document.querySelector("#connection-status").style.display = "inherit";
            document.querySelector("#connection-error").innerHTML = reason;
        }
    };

    var version = null;

    function update() {
        get_json('api/v1/servers/localhost/statistics').then((adata) => {
                connectionOK(true);

                var data = {};
                adata.forEach((statItem) => {
                    data[statItem.name] = statItem.value;
                });

                if (!gdata["sys-msec"])
                    gdata = data;

                var cpu = 0.1 * (1.0 * data["sys-msec"] + 1.0 * data["user-msec"]
                                 - 1.0 * gdata["sys-msec"] - 1.0 * gdata["user-msec"]);
                var qps = 1.0 * data["questions"] - 1.0 * gdata["questions"];
                var servfailps = 1.0 * data["servfail-answers"] - 1.0 * gdata["servfail-answers"];
                var totpcache = 1.0 * data["packetcache-hits"] - 1.0 * gdata["packetcache-hits"] +
                                1.0 * data["packetcache-misses"] - 1.0 * gdata["packetcache-misses"];
                var phitrate = 0;
                if (totpcache > 0) {
                    phitrate = 100.0 * (data["packetcache-hits"] - 1.0 * gdata["packetcache-hits"]) / totpcache;
                }

                var stats = {
                    version: version || '...',
                    questions: data["questions"],
                    over_capacity_drops: data["over-capacity-drops"],
                    too_old: data["too-old-drops"],
                    uptime: moment.duration(data["uptime"] * 1000.0).humanize(),
                    latency: data["qa-latency"] / 1000.0,
                    cpu: cpu.toFixed(2),
                    qps: qps,
                    phitrate: phitrate.toFixed(2)
                };
                render('top-stats', stats);

                qpsgraph.series.addData({qps: qps, servfailps: servfailps});
                qpsgraph.render();

                cpugraph.series.addData({one: cpu});
                cpugraph.render();

                gdata = data;
        }).catch((reason) => {
            connectionOK(false, reason);
        });

        if (!version) {
            get_json('api/v1/servers/localhost').then((data) => {
                version = "PowerDNS " + data["daemon_type"] + " " + data["version"]
            });
        }

        if ((intervalcount++) % 5)
            return;
        updateRingBuffers();
    }

    document.querySelector("#filter1").addEventListener('click', updateRingBuffers);

    update();
    setInterval(update, 1000);
}

// rely on "defer" on <script> tag for document to be ready before running.
startup();
