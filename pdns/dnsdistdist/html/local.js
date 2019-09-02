"use strict";

var gdata={}

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
    var y_ticks = new Rickshaw.Graph.Axis.Y( {
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
    var y_ticks = new Rickshaw.Graph.Axis.Y( {
        graph: cpugraph,
        orientation: 'left',
        tickFormat: Rickshaw.Fixtures.Number.formatKMBT,
        element: document.getElementById('cpuy_axis')
    } );

    cpugraph.render();
    var intervalcount=0;

    function updateRingBuffers()
    {
        var filtered=$("#filter1").is(':checked')
        var qstring='jsonstat?command=get-query-ring&name=queries';
        if(filtered)
            qstring=qstring+"&public-filtered=1";

        $.getJSON(qstring,
                  function(data) {
                      console.log(data);
                      var bouw="<table><tr><th>Number</th><th>Domain</th><th>Type</th></tr>";
                      var num=0;
                      var total=0, rest=0;
                      $.each(data["entries"], function(a,b) {
                          total+=b[0];
                          if(num++ > 10) {
                              rest+=b[0];
                              return;
                          }
                          if(b[1].length > 25)
                              b[1]=b[1].substring(0,25);

                          bouw=bouw+("<tr><td>"+b[0]+"</td><td>"+b[1]+"</td><td>"+b[2]+"</td></tr>");
                      });
                      bouw+="<tr><td>"+rest+"</td><td>Rest</td></tr>";
                      bouw=bouw+"</table>";
                      $("#queryring").html(bouw);

                  });

        filtered=$("#filter2").is(':checked')
        qstring='jsonstat?command=get-query-ring&name=servfail-queries';
        if(filtered)
            qstring=qstring+"&public-filtered=1";

        $.getJSON(qstring, 
                  function(data) {
                      var bouw="<table><tr><th>Number</th><th>Servfail domain</th><th>Type</th></tr>";
                      var num=0, total=0, rest=0;
                      $.each(data["entries"], function(a,b) {
                          total+=b[0];
                          if(num++ > 10) {
                              rest+=b[0];
                              return;
                          }
                          if(b[1].length > 25)
                              b[1]=b[1].substring(0,25);
                          bouw=bouw+("<tr><td>"+b[0]+"</td><td>"+b[1]+"</td><td>"+b[2]+"</td></tr>");
                      });
                      bouw+="<tr><td>"+rest+"</td><td>Rest</td></tr>";
                      bouw=bouw+"</table>";
                      $("#servfailqueryring").html(bouw);

                  });

        $.getJSON('jsonstat?command=get-remote-ring&name=remotes', 
                  function(data) {
                      var bouw="<table><tr><th>Number</th><th>Remote</th></tr>";
                      var num=0, total=0, rest=0;
                      $.each(data["entries"], function(a,b) {
                          total+=b[0];
                          if(num++ > 10) {
                              rest +=b[0];
                              return;
                          }
                          bouw=bouw+("<tr><td>"+b[0]+"</td><td>"+b[1]+"</td></tr>");
                      });
                      bouw+="<tr><td>"+rest+"</td><td>Rest</td></tr>";
                      bouw=bouw+"</table>";
                      $("#remotering").html(bouw);

                  });

        $.getJSON('jsonstat?command=get-remote-ring&name=servfail-remotes', 
                  function(data) {
                      var bouw="<table><tr><th>Number</th><th>Servfail Remote</th></tr>";
                      var num=0, total=0, rest=0;
                      $.each(data["entries"], function(a,b) {
                          total+=b[0];
                          if(num++ > 10) {
                              rest += b[0];
                              return;
                          }
                          bouw=bouw+("<tr><td>"+b[0]+"</td><td>"+b[1]+"</td></tr>");
                      });
                      bouw+="<tr><td>"+rest+"</td><td>Rest</td></tr>";
                      bouw=bouw+"</table>";
                      $("#servfailremotering").html(bouw);
                  });
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
                if(!gdata["cpu-sys-msec"]) 
                    gdata=data;

                var cpu=((1.0*data["cpu-sys-msec"]+1.0*data["cpu-user-msec"] - 1.0*gdata["cpu-sys-msec"]-1.0*gdata["cpu-user-msec"])/10.0);

                $("#cpu").text(cpu.toFixed(2));
                var qps=1.0*data["queries"]-1.0*gdata["queries"];
                $("#qps").text(qps.toFixed(2));
                $("#server-policy").text(data["server-policy"]);

                var servfailps=1.0*data["servfail-responses"]-1.0*gdata["servfail-responses"];

                var totpcache=1.0*data["cache-hits"]-1.0*gdata["cache-hits"]+1.0*data["cache-misses"]-1.0*gdata["cache-misses"];
                var hitrate=0;
                if(totpcache > 0) {
                    hitrate=100.0*(data["cache-hits"]-1.0*gdata["cache-hits"])/totpcache;
                    $("#phitrate").text(hitrate.toFixed(2));
                }
                else
                    $("#phitrate").text(0);
                
                qpsgraph.series.addData({ qps: qps, servfailps: servfailps});
                qpsgraph.render();

                cpugraph.series.addData({ one: cpu, two: hitrate});
                cpugraph.render();

                gdata=data;
            },
            error:  function() {

            },
        });
        
        $.ajax({ url: 'api/v1/servers/localhost', type: 'GET', dataType: 'json', jsonp: false,
                 success: function(data) {
                     $("#version").text(data["daemon_type"]+" "+data["version"]);
                     $("#acl").text(data["acl"]);
                     $("#local").text(data["local"]);
                     var bouw='<table width="100%"><tr align=right><th>#</th><th align=left>Name</th><th align=left>Address</th><th>Status</th><th>Latency</th><th>Queries</th><th>Drops</th><th>QPS</th><th>Out</th><th>Weight</th><th>Order</th><th align=left>Pools</th></tr>';
                     $.each(data["servers"], function(a,b) {
                         bouw = bouw + ("<tr align=right><td>"+b["id"]+"</td><td align=left>"+b["name"]+"</td><td align=left>"+b["address"]+"</td><td>"+b["state"]+"</td>");
                         var latency = (b["latency"] === null) ? 0.0 : b["latency"];
                         bouw = bouw + ("<td>"+latency.toFixed(2)+"</td><td>"+b["queries"]+"</td><td>"+b["reuseds"]+"</td><td>"+(b["qps"]).toFixed(2)+"</td><td>"+b["outstanding"]+"</td>");
                         bouw = bouw + ("<td>"+b["weight"]+"</td><td>"+b["order"]+"</td><td align=left>"+b["pools"]+"</td></tr>");
                     }); 
                     bouw = bouw + "</table>";
                     $("#downstreams").html(bouw);
                     
                     bouw='<table width="100%"><tr align=left><th>#</th><th align=left>Rule</th><th>Action</th><th>Matches</th></tr>';
                     if(data["rules"].length) {
                         $.each(data["rules"], function(a,b) {
                             bouw = bouw + ("<tr align=left><td>"+b["id"]+"</td><td align=left>"+b["rule"]+"</td><td>"+b["action"]+"</td>");
                             bouw = bouw + ("<td>"+b["matches"]+"</td></tr>");
                         }); 
                     }
                     else
                         bouw = bouw + '<tr><td align="center" colspan="4"><font color="#aaaaaa">No rules defined</font></td></tr>';
                     bouw = bouw + "</table>";
                     $("#rules").html(bouw);

                     bouw='<table width="100%"><tr align=left><th>#</th><th align=left>Response Rule</th><th>Action</th><th>Matches</th></tr>';
                     if(data["response-rules"].length) {
                         $.each(data["response-rules"], function(a,b) {
                             bouw = bouw + ("<tr align=left><td>"+b["id"]+"</td><td align=left>"+b["rule"]+"</td><td>"+b["action"]+"</td>");
                             bouw = bouw + ("<td>"+b["matches"]+"</td></tr>");
                         });
                     }
                     else
                         bouw = bouw + '<tr><td align="center" colspan="4"><font color="#aaaaaa">No response rules defined</font></td></tr>';
                     bouw = bouw + "</table>";
                     $("#response-rules").html(bouw);
                 }
               });


//        if((intervalcount++)%5)
  //          return;
        //      updateRingBuffers();

        $.ajax({ url: 'jsonstat?command=dynblocklist', type: 'GET', dataType: 'json', jsonp: false,
                 success: function(data) {
                     var bouw='<table width="100%"><tr align=left><th>Dyn blocked netmask</th><th>Seconds</th><th>Blocks</th><th align=left>Reason</th></tr>';
		     var gotsome=false;
                     $.each(data, function(a,b) {
                         bouw=bouw+("<tr><td>"+a+"</td><td>"+b.seconds+"</td><td>"+b.blocks+"</td><td>"+b.reason+"</td></tr>");
			 gotsome=true;
                     });
                     
		     if(!gotsome)
                         bouw = bouw + '<tr><td align="center" colspan="4"><font color="#aaaaaa">No dynamic blocks active</font></td></tr>';

                     bouw=bouw+"</table>";
                     $("#dynblock").html(bouw);

                 }});

        $.ajax({ url: 'jsonstat?command=ebpfblocklist', type: 'GET', dataType: 'json', jsonp: false,
                 success: function(data) {
                     var bouw='<table width="100%"><tr align=left><th>Kernel-based dyn blocked netmask</th><th>Seconds</th></th><th>Blocks</th></tr>';
		     var gotsome=false;
                     $.each(data, function(a,b) {
                         bouw=bouw+("<tr><td>"+a+"</td><td>"+b.seconds+"</td><td>"+b.blocks+"</td></tr>");
			 gotsome=true;
                     });

		     if(!gotsome)
                         bouw = bouw + '<tr><td align="center" colspan="4"><font color="#aaaaaa">No eBPF blocks active</font></td></tr>';

                     bouw=bouw+"</table>";
                     $("#ebpfblock").html(bouw);

                 }});

    };
    
    $("#filter1").click(updateRingBuffers);
    $("#filter2").click(updateRingBuffers);

    update();
    setInterval(update, 1000);
});
