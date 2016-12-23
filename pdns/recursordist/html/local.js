"use strict";

// var moment= require('moment');
var gdata={}

$(document).ready(function() {
    $.ajaxSetup({ cache: false });
    
    var password=$("#password").val();
    $("#password").change(function(e) {
	password=$("#password").val();
        update();
    });

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
	series: new Rickshaw.Series.FixedDuration([{ name: 'one' }], undefined, {
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
	var qstring='jsonstat?api-key='+password+'&command=get-query-ring&name=queries';

	if(filtered)
	    qstring=qstring+"&public-filtered=1";

	$.getJSON(qstring,
		  function(data) {
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
	qstring='jsonstat?api-key='+password+'&command=get-query-ring&name=servfail-queries';

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

	$.getJSON('jsonstat?api-key='+password+'&command=get-remote-ring&name=remotes', 
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

	$.getJSON('jsonstat?api-key='+password+'&command=get-remote-ring&name=servfail-remotes', 
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
            url: 'api/v1/servers/localhost/statistics?api-key='+password,
            type: 'GET',
            dataType: 'json',
            success: function(adata, x, y) {
                $("#connection-status").hide();
                $("#connection-error").html("");
		var data={};
		$.each(adata, function(key, val) {
		    data[val.name]=val.value;
		});
		$("#questions").text(data["questions"]);
		$("#over-capacity-drops").text(data["over-capacity-drops"]);
		$("#too-old").text(data["too-old-drops"]);
		$("#uptime").text(moment.duration(data["uptime"]*1000.0).humanize());
		$("#latency").text(data["qa-latency"]/1000.0);
		if(!gdata["sys-msec"]) 
		    gdata=data;

		var cpu=((1.0*data["sys-msec"]+1.0*data["user-msec"] - 1.0*gdata["sys-msec"]-1.0*gdata["user-msec"])/10.0);

		$("#cpu").text(cpu.toFixed(2));
		var qps=1.0*data["questions"]-1.0*gdata["questions"];
		$("#qps").text(qps);

		var servfailps=1.0*data["servfail-answers"]-1.0*gdata["servfail-answers"];

		var totpcache=1.0*data["packetcache-hits"]-1.0*gdata["packetcache-hits"]+1.0*data["packetcache-misses"]-1.0*gdata["packetcache-misses"];
		if(totpcache > 0)
		    $("#phitrate").text((100.0*(data["packetcache-hits"]-1.0*gdata["packetcache-hits"])/totpcache).toFixed(2));
		else
		    $("#phitrate").text(0);
		
		qpsgraph.series.addData({ qps: qps, servfailps: servfailps});
		qpsgraph.render();

		cpugraph.series.addData({ one: cpu});
		cpugraph.render();

		gdata=data;
            },
            error:  function(o) {
                $("#connection-status").show();
                $("#connection-error").html(o.status+" "+o.statusText);
            },
            beforeSend: function(xhr) { 
                xhr.setRequestHeader('X-API-Key', 'changeme');
		
		
		return true;
	    }
        });
	
	$.ajax({ url: 'api/v1/servers/localhost?api-key='+password, type: 'GET', dataType: 'json',
		 success: function(data) {
		     $("#version").text("PowerDNS "+data["daemon_type"]+" "+data["version"]);
		 }
	       });


	if((intervalcount++)%5)
	    return;
	updateRingBuffers();


    };
		 
    $("#filter1").click(updateRingBuffers);
    $("#filter2").click(updateRingBuffers);

    update();
    setInterval(update, 1000);
});
