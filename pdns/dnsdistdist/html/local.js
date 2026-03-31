"use strict";

var gdata = {}

$(document).ready(function() {
    $.ajaxSetup({ cache: false });

    var qpsgraph = new Rickshaw.Graph( {
        element: document.getElementById("qpschart"),
        width: 400,
        height: 200,
        renderer: 'line',
        series: new Rickshaw.Series.FixedDuration([{ name: 'servfailps' }, {name: 'qps'}], undefined, {
            timeInterval: 1000,
            maxDataPoints: 100,
            timeBase: new Date().getTime() / 1000
        })
    } );
    new Rickshaw.Graph.Axis.Y( {
        graph: qpsgraph,
        orientation: 'left',
        tickFormat: Rickshaw.Fixtures.Number.formatKMBT,
        element: document.getElementById('qpsy_axis')
    } );

    qpsgraph.render();

    var cpugraph = new Rickshaw.Graph( {
        element: document.getElementById("cpuchart"),
        width: 400,
        height: 200,
        renderer: 'line',
        series: new Rickshaw.Series.FixedDuration([{ name: 'one' }, {name: 'two'}], undefined, {
            timeInterval: 1000,
            maxDataPoints: 100,
            timeBase: new Date().getTime() / 1000
        })
    } );
    new Rickshaw.Graph.Axis.Y( {
        graph: cpugraph,
        orientation: 'left',
        tickFormat: Rickshaw.Fixtures.Number.formatKMBT,
        element: document.getElementById('cpuy_axis')
    } );

    cpugraph.render();

    function appendCellToRow(row, untrusted, align)
    {
        var cell = $('<td/>');
        if (align) {
            cell =  $('<td align=' + align + '/>');
        }
        cell.text(untrusted);
        row.append(cell);
    }

    function update()
    {
        $.ajax({
            url: 'jsonstat?command=stats',
            type: 'GET',
            dataType: 'json',
            jsonp: false,
            success: function(data, x, y) {
                $("#questions").text(data["queries"]);
                $("#acl-drops").text(data["acl-drops"]);
                $("#dyn-drops").text(data["dyn-blocked"]);
                $("#rule-drops").text(data["rule-drop"]);
                $("#uptime").text(moment.duration(data["uptime"]*1000.0).humanize());
                $("#latency").text((data["latency-avg10000"]/1000.0).toFixed(2));
                $("#latency-tcp").text((data["latency-tcp-avg10000"]/1000.0).toFixed(2));
                $("#latency-dot").text((data["latency-dot-avg10000"]/1000.0).toFixed(2));
                $("#latency-doh").text((data["latency-doh-avg10000"]/1000.0).toFixed(2));
                $("#latency-doq").text((data["latency-doq-avg10000"]/1000.0).toFixed(2));
                if (!gdata["cpu-sys-msec"]) {
                    gdata = data;
                }

                var cpu = ((1*data["cpu-sys-msec"] + 1*data["cpu-user-msec"]) - (1*gdata["cpu-sys-msec"] + 1*gdata["cpu-user-msec"]))/10.0;

                $("#cpu").text(cpu.toFixed(2));
                var qps = 1.0*data["queries"]-1.0*gdata["queries"];
                $("#qps").text(qps.toFixed(2));
                $("#server-policy").text(data["server-policy"]);

                var servfailps = (1*data["servfail-responses"]) - (1*gdata["servfail-responses"]);

                var totpcache = (1*data["cache-hits"] + 1*data["cache-misses"]) - (1*gdata["cache-hits"] + 1*gdata["cache-misses"]);
                var hitrate = 0;
                if (totpcache > 0) {
                    hitrate = 100.0*(data["cache-hits"]-1.0*gdata["cache-hits"])/totpcache;
                    $("#phitrate").text(hitrate.toFixed(2));
                }
                else {
                    $("#phitrate").text(0);
                }

                qpsgraph.series.addData({ qps: qps, servfailps: servfailps});
                qpsgraph.render();

                cpugraph.series.addData({ one: cpu, two: hitrate});
                cpugraph.render();

                gdata = data;
            },
            error:  function() {

            },
        });

        $.ajax({ url: 'api/v1/servers/localhost', type: 'GET', dataType: 'json', jsonp: false,
                 success: function(data) {
                     $("#version").text(data["daemon_type"]+" "+data["version"]);
                     $("#acl").text(data["acl"]);
                     $("#local").text(data["local"]);
                     var tableElement = $('<table width="100%"><tr align=right><th>#</th><th align=left>Name</th><th align=left>Address</th><th>Status</th><th>UDP Latency</th><th>TCP Latency</th><th>Queries</th><th>Drops</th><th>QPS</th><th>Out</th><th>Weight</th><th>Order</th><th align=left>Pools</th></tr></table>');
                     $.each(data["servers"], function(a,b) {
                         var row = $('<tr align=right/>');
                         var latency = (b["latency"] === null || b["latency"] === 0.0) ? "-" : b["latency"].toFixed(2);
                         var tcpLatency = (b["tcpLatency"] === null || b["tcpLatency"] === 0.0) ? "-" : b["tcpLatency"].toFixed(2);
                         appendCellToRow(row, b["id"]);
                         appendCellToRow(row, b["name"], 'left');
                         appendCellToRow(row, b["address"], 'left');
                         appendCellToRow(row, b["state"]);
                         appendCellToRow(row, latency);
                         appendCellToRow(row, tcpLatency);
                         appendCellToRow(row, b["queries"]);
                         appendCellToRow(row, b["reused"]);
                         appendCellToRow(row, b["qps"].toFixed(2));
                         appendCellToRow(row, b["outstanding"]);
                         appendCellToRow(row, b["weight"]);
                         appendCellToRow(row, b["order"]);
                         appendCellToRow(row, b["pools"], 'left');
                         tableElement.append(row);
                     });
                     $("#downstreams").html(tableElement);

                     tableElement = $('<table width="100%"><tr align=left><th>#</th><th align=left>Name</th><th align=left>Rule</th><th>Action</th><th>Matches</th></tr></table>');
                     if (data["rules"].length) {
                         $.each(data["rules"], function(a,b) {
                             var row = $('<tr align=left />');
                             appendCellToRow(row, b["id"]);
                             appendCellToRow(row, b["name"], 'left');
                             appendCellToRow(row, b["rule"], 'left');
                             appendCellToRow(row, b["action"]);
                             appendCellToRow(row, b["matches"]);
                             tableElement.append(row);
                         });
                     }
                     else {
                         tableElement.append($('<tr><td align="center" colspan="4"><font color="#aaaaaa">No rules defined</font></td></tr>'));
                     }
                     $("#rules").html(tableElement);

                     tableElement = $('<table width="100%"><tr align=left><th>#</th><th align=left>Name</th><th align=left>Response Rule</th><th>Action</th><th>Matches</th></tr></table>');
                     if (data["response-rules"].length) {
                         $.each(data["response-rules"], function(a,b) {
                             var row = $('<tr align=left />');
                             appendCellToRow(row, b["id"]);
                             appendCellToRow(row, b["name"], 'left');
                             appendCellToRow(row, b["rule"], 'left');
                             appendCellToRow(row, b["action"]);
                             appendCellToRow(row, b["matches"]);
                             tableElement.append(row);
                         });
                     }
                     else {
                         tableElement.append($('<tr><td align="center" colspan="4"><font color="#aaaaaa">No response rules defined</font></td></tr>'));
                     }
                     $("#response-rules").html(tableElement);
                 }
               });

        $.ajax({ url: 'jsonstat?command=dynblocklist', type: 'GET', dataType: 'json', jsonp: false,
                 success: function(data) {
                     var tableElement = $('<table width="100%"><tr align=left><th>Dyn blocked netmask</th><th>Seconds</th><th>Blocks</th><th>eBPF</th><th align=left>Reason</th></tr></table>');
                     var gotsome = false;
                     $.each(data, function(a,b) {
                         var row = $('<tr/>');
                         appendCellToRow(row, a);
                         appendCellToRow(row, b.seconds);
                         appendCellToRow(row, b.blocks);
                         appendCellToRow(row, b.ebpf);
                         appendCellToRow(row, b.reason);
                         tableElement.append(row);
                         gotsome = true;
                     });

                     if (!gotsome) {
                         tableElement.append($('<tr><td align="center" colspan="4"><font color="#aaaaaa">No dynamic blocks active</font></td></tr>'));
                     }

                     $("#dynblock").html(tableElement);
                 }});

        $.ajax({ url: 'jsonstat?command=ebpfblocklist', type: 'GET', dataType: 'json', jsonp: false,
                 success: function(data) {
                     var tableElement = $('<table width="100%"><tr align=left><th>Kernel-based dyn blocked netmask</th><th>Seconds</th></th><th>Blocks</th></tr>');
                     var gotsome = false;
                     $.each(data, function(a,b) {
                         var row = $('<tr/>');
                         appendCellToRow(row, a);
                         appendCellToRow(row, b.seconds);
                         appendCellToRow(row, b.blocks);
                         tableElement.append(row);
                         gotsome = true;
                     });

                     if (!gotsome) {
                         tableElement.append($('<tr><td align="center" colspan="4"><font color="#aaaaaa">No eBPF blocks active</font></td></tr>'));
                     }

                     $("#ebpfblock").html(tableElement);
                 }});
    };

    update();
    setInterval(update, 1000);
});
