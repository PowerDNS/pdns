/* the name ends with .sql because of (some) nice colours in mcedit ;-) */


mongo table domains
    { 	"domain_id" : int, 
	"name" : string, 
	"last_check" : int, 
	"notified_serial" : int, 
	"type" : string, 
	"ttl" : int,
	"account" : string, 
	"SOA" : {
	    "serial" : int,
	    "refresh" : int,
	    "retry" : int,
	    "expire" : int,
	    "default_ttl" : int,
	    "hostmaster" : string
	},
	"masters" : [ string, ... ], 
    }
    
mongo table record
    { 	"domain_id" : int , 
	"name" : string, 
	"type" : string, 
	"ttl" : int, 
	"ordername" : string,
	"auth" : bool,
	"content" : [ 
	    { 	"prio" : int, 
		"ttl" : int, 
		"data" : string 
	    }
	    , ... 
	]

mongo table domainmetadata 
    { 	"name" : string , 
	"content" : [ 
	    { 	"kind" : string, 
		"data" : [ string, ...] 
	    }
	    , ... 
	] 
    }

mongo table cryptokeys
    { 	"domain_id" : int, 
	"name" : string , 
	"content" : [ 
	    { 	"id" : int, 
		"flags" : int, 
		"active" : bool, 
		"data" : string 
	    }
	    , ... 
	] 
    }

mongo table tsigkeys 
    { 	"name" : string, 
	"content" : [ 
	    {	"algorithm" : string, 
		"secret" : string 
	    }
	    , ... 
	] 
    }


