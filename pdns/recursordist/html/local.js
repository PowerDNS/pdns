"use strict";

// var moment= require('moment');
var gdata = {};

$(document).ready(function () {
    $.ajaxSetup({cache: false});

    var getTemplate = function (name) {
        var template = $('#' + name + '-template').html();
        return Handlebars.compile(template);
    };
    var cachedTemplates = {};
    var render = function (name, ctx) {
        var t = cachedTemplates[name];
        if (!t) {
            t = getTemplate(name);
            cachedTemplates[name] = t;
        }
        var h = t(ctx);
        $('#' + name).html(h);
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
        $.each(data["entries"], function (a, b) {
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
        $.getJSON('jsonstat', jsonstatParams('get-query-ring', 'queries', $("#filter1").is(':checked')),
            function (data) {
                var rows = makeRingRows(data);
                render('queryring', {rows: rows});
            });

        $.getJSON('jsonstat', jsonstatParams('get-query-ring', 'servfail-queries', $("#filter1").is(':checked')),
            function (data) {
                var rows = makeRingRows(data);
                render('servfailqueryring', {rows: rows});
            });

        $.getJSON('jsonstat', jsonstatParams('get-query-ring', 'bogus-queries', $("#filter1").is(':checked')),
            function (data) {
                var rows = makeRingRows(data);
                render('bogusqueryring', {rows: rows});
            });

        $.getJSON('jsonstat', jsonstatParams('get-remote-ring', 'remotes', false),
            function (data) {
                var rows = makeRingRows(data);
                render('remotering', {rows: rows});
            });

        $.getJSON('jsonstat', jsonstatParams('get-remote-ring', 'servfail-remotes', false),
            function (data) {
                var rows = makeRingRows(data);
                render('servfailremotering', {rows: rows});
            });

        $.getJSON('jsonstat', jsonstatParams('get-remote-ring', 'bogus-remotes', false),
            function (data) {
                var rows = makeRingRows(data);
                render('bogusremotering', {rows: rows});
            });
        $.getJSON('jsonstat', jsonstatParams('get-remote-ring', 'timeouts', false),
            function (data) {
                var rows = makeRingRows(data);
                render('timeouts', {rows: rows});
            });
    }

    var connectionOK = function (ok, o) {
        if (ok) {
            $("#connection-status").hide();
            $("#connection-error").html("");
            $("#content-hidden-on-load").show();
        } else {
            $("#connection-status").show();
            $("#connection-error").html(o.status + " " + o.statusText);
        }
    };

    var version = null;

    function update() {
        $.ajax({
            url: 'api/v1/servers/localhost/statistics',
            type: 'GET',
            dataType: 'json',
            success: function (adata, x, y) {
                connectionOK(true);

                var data = {};
                $.each(adata, function (key, val) {
                    data[val.name] = val.value;
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
            },
            error: function (o) {
                connectionOK(false, o);
            },
            beforeSend: function (xhr) {
                xhr.setRequestHeader('X-API-Key', 'changeme');
                return true;
            }
        });

        if (!version) {
            $.ajax({
                url: 'api/v1/servers/localhost', type: 'GET', dataType: 'json',
                success: function (data) {
                    version = "PowerDNS " + data["daemon_type"] + " " + data["version"];
                }
            });
        }

        if ((intervalcount++) % 5)
            return;
        updateRingBuffers();
    }

    $("#filter1").click(updateRingBuffers);
    $("#filter2").click(updateRingBuffers);

    update();
    setInterval(update, 1000);
});
