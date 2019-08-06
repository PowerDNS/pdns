Backend writers' guide
======================

PowerDNS backends are implemented via a simple yet powerful C++
interface. If your needs are not met by the PipeBackend, you may want to
write your own. Before doing any PowerDNS development, please read `this blog
post <https://blog.powerdns.com/2015/06/23/what-is-a-powerdns-backend-and-how-do-i-make-it-send-an-nxdomain/>`__
which has a FAQ and several pictures that help explain what a backend
is.

A backend contains zero DNS logic. It need not look for CNAMEs, it need
not return NS records unless explicitly asked for, etcetera. All DNS
logic is contained within PowerDNS itself - backends should simply
return records matching the description asked for.

.. warning::
  However, please note that your backend can get queries in
  aNy CAsE! If your database is case sensitive, like most are (with the
  notable exception of MySQL), you must make sure that you do find answers
  which differ only in case.

.. warning::
  PowerDNS may instantiate multiple instances of your
  backend, or destroy existing copies and instantiate new ones. Backend
  code should therefore be thread-safe with respect to its static data.
  Additionally, it is wise if instantiation is a fast operation, with the
  possible exception of the first construction.

Notes
-----

Besides regular query types, the DNS also knows the 'ANY' query type.
When a server receives a question for this ANY type, it should reply
with all record types available.

Backends should therefore implement being able to answer 'ANY' queries
in this way, and supply all record types they have when they receive
such an 'ANY' query. This is reflected in the sample script above, which
for every qtype answers if the type matches, or if the query is for
'ANY'.

However, since backends need to implement the ANY query anyhow, PowerDNS
makes use of this. Since almost all DNS queries internally need to be
translated first into a CNAME query and then into the actual query,
possibly followed by a SOA or NS query (this is how DNS works
internally), it makes sense for PowerDNS to speed this up, and just ask
the ANY query of a backend.

When it has done so, it gets the data about SOA, CNAME and NS records in
one go. This speeds things up tremendously.

The upshot of the above is that for any backend, including the PIPE
backend, implementing the ANY query is NOT optional. And in fact, a
backend may see almost exclusively ANY queries. This is not a bug.

Simple read-only native backends
--------------------------------

Implementing a backend consists of inheriting from the DNSBackend class.
For read-only backends, which do not support slave operation, only the
following methods are relevant:

.. code-block:: cpp

        class DNSBackend
        {
        public:

        virtual void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1)=0;
        virtual bool list(const string &target, int domain_id)=0;
        virtual bool get(DNSResourceRecord &r)=0;
        virtual bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0);
        };

Note that the first three methods must be implemented. ``getSOA()`` has
a useful default implementation.

The semantics are simple. Each instance of your class only handles one
(1) query at a time. There is no need for locking as PowerDNS guarantees
that your backend will never be called reentrantly.

.. note::
  Queries for wildcard names should be answered literally,
  without expansion. So, if a backend gets a question for
  "\*.powerdns.com", it should only answer with data if there is an actual
  "\*.powerdns.com" name

Some examples, a more formal specification is down below. A normal
lookup starts like this:

.. code-block:: cpp

        YourBackend yb;
        yb.lookup(QType::CNAME,"www.powerdns.com");

Your class should now do everything to start this query. Perform as much
preparation as possible - handling errors at this stage is better for
PowerDNS than doing so later on. A real error should be reported by
throwing an exception.

PowerDNS will then call the ``get()`` method to get
``DNSResourceRecord``\ s back. The following code illustrates a typical
query:

.. code-block:: cpp

        yb.lookup(QType::CNAME,"www.powerdns.com");

        DNSResourceRecord rr;
        while(yb.get(rr))
          cout<<"Found cname pointing to '"+rr.content+"'"<<endl;
        }

Each zone starts with a Start of Authority (SOA) record. This record is
special so many backends will choose to implement it specially. The
default ``getSOA()`` method performs a regular lookup on your backend to
figure out the SOA, so if you have no special treatment for SOA records,
where is no need to implement your own ``getSOA()``.

Besides direct queries, PowerDNS also needs to be able to list a zone,
to do zone transfers for example. Each zone has an id which should be
unique within the backend. To list all records belonging to a zone id,
the ``list()`` method is used. Conveniently, the domain_id is also
available in the ``SOAData`` structure.

The following lists the contents of a zone called "powerdns.com".

.. code-block:: cpp

        SOAData sd;
        if(!yb.getSOA("powerdns.com",sd))  // are we authoritative over powerdns.com?
          return RCode::NotAuth;           // no

        yb.list(sd.domain_id);
        while(yb.get(rr))
          cout<<rr.qname<<"\t IN "<<rr.qtype.getName()<<"\t"<<rr.content<<endl;

A sample minimal backend
------------------------

This backend only knows about the host "random.powerdns.com", and
furthermore, only about its A record:

.. code-block:: cpp

    /* FIRST PART */
    class RandomBackend : public DNSBackend
    {
    public:
      bool list(const string &target, int id)
      {
        return false; // we don't support AXFR
      }

      void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId)
      {
        if(type.getCode()!=QType::A || qdomain!="random.powerdns.com")  // we only know about random.powerdns.com A
          d_answer="";                                                  // no answer
        else {
          ostringstream os;
          os<<random()%256<<"."<<random()%256<<"."<<random()%256<<"."<<random()%256;
          d_answer=os.str();                                           // our random ip address
        }
      }

      bool get(DNSResourceRecord &rr)
      {
        if(!d_answer.empty()) {
          rr.qname="random.powerdns.com";                               // fill in details
          rr.qtype=QType::A;                                            // A record
          rr.ttl=86400;                                                 // 1 day
          rr.content=d_answer;

          d_answer="";                                                  // this was the last answer

          return true;
        }
        return false;                                                   // no more data
      }

    private:
      string d_answer;
    };

    /* SECOND PART */

    class RandomFactory : public BackendFactory
    {
    public:
      RandomFactory() : BackendFactory("random") {}

      DNSBackend *make(const string &suffix)
      {
        return new RandomBackend();
      }
    };

    /* THIRD PART */

    class RandomLoader
    {
    public:
      RandomLoader()
      {
        BackendMakers().report(new RandomFactory);
        g_log << Logger::Info << "[randombackend] This is the random backend version " VERSION " reporting" << endl;
      }
    };

    static RandomLoader randomloader;

This simple backend can be used as an 'overlay'. In other words, it only
knows about a single record, another loaded backend would have to know
about the SOA and NS records and such. But nothing prevents us from
loading it without another backend.

The first part of the code contains the actual logic and should be
pretty straightforward. The second part is a boilerplate 'factory' class
which PowerDNS calls to create randombackend instances. Note that a
'suffix' parameter is passed. Real life backends also declare parameters
for the configuration file; these get the 'suffix' appended to them.
Note that the "random" in the constructor denotes the name by which the
backend will be known.

The third part registers the RandomFactory with PowerDNS. This is a
simple C++ trick which makes sure that this function is called on
execution of the binary or when loading the dynamic module.

Please note that a RandomBackend is actually in most PowerDNS releases.
By default it lives on random.example.com, but you can change that by
setting :ref:`setting-random-hostname`.

.. note::
  This simple backend neglects to handle case properly!

Interface definition
--------------------

Classes
~~~~~~~

.. cpp:class:: DNSResourceRecord

.. cpp:member:: std::string DNSResourceRecord::qname

  Name of this record

.. cpp:member:: QType DNSResourceRecord::qtype

  Query type of this record

.. cpp:member:: std::string DNSResourceRecord::content

  ASCII representation of the right-hand side

.. cpp:member:: uint32_t DNSResourceRecord::ttl

  Time To Live of this record

.. cpp:member:: int DNSResourceRecord::domain_id

  ID of the domain this record belongs to

.. cpp:member:: time_t DNSResourceRecord::last_modified

   If unzero, last time_t this record was changed

.. cpp:member:: bool DNSResourceRecord::auth

  Used for DNSSEC operations. See :doc:`../dnssec/migration`. 
  It is also useful to check out the ``rectifyZone()`` in pdnsutil.cc.

.. cpp:member:: bool DNSResourceRecord::disabled

  If set, this record is not to be served to DNS clients.
  Backends should not make these records available to PowerDNS unless indicated otherwise.

.. cpp:class:: SOAData

.. cpp:member:: string SOAData::nameserver

  Name of the master nameserver of this zone

.. cpp:member:: string SOAData::hostmaster

  Hostmaster of this domain. May contain an @

.. cpp:member:: uint32_t SOAData::serial

  Serial number of this zone

.. cpp:member:: uint32_t SOAData::refresh

  How often this zone should be refreshed

.. cpp:member:: uint32_t SOAData::retry

  How often a failed zone pull should be retried.

.. cpp:member:: u_int32_t SOAData::expire

  If zone pulls failed for this long, retire records

.. cpp:member:: uint32_t SOAData::default_ttl

  Difficult

.. cpp:member:: int SOAData::domain_id

  The ID of the domain within this backend. Must be filled!

.. cpp:member:: DNSBackend* SOAData::db

  Pointer to the backend that feels authoritative for a domain and can act as a slave

Methods
~~~~~~~

.. cpp:function:: void DNSBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt=0, int zoneId=-1)

  This function is used to initiate a straight lookup for a record of name
  'qdomain' and type 'qtype'. A QType can be converted into an integer by
  invoking its ``getCode()`` method and into a string with the
  ``getCode()``.

  The original question may or may not be passed in the pointer pkt. If it
  is, you can retrieve information about who asked the question with the
  ``pkt->getRemote()`` method.

  Note that **qdomain** can be of any case and that your backend should
  make sure it is in effect case insensitive. Furthermore, the case of the
  original question should be retained in answers returned by ``get()``!

  Finally, the domain_id might also be passed indicating that only
  answers from the indicated zone need apply. This can both be used as a
  restriction or as a possible speedup, hinting your backend where the
  answer might be found.

  If initiated successfully, as indicated by returning **true**, answers
  should be made available over the ``get()`` method.

  Should throw an PDNSException if an error occurred accessing the
  database. Returning otherwise indicates that the query was started
  successfully. If it is known that no data is available, no exception
  should be thrown! An exception indicates that the backend considers
  itself broken - not that no answers are available for a question.

  It is legal to return here, and have the first call to ``get()`` return
  false. This is interpreted as 'no data'.

.. cpp:function:: bool DNSBackend::list(int domain_id, bool include_disabled=false)

  Initiates a list of the indicated domain. Records should then be made
  available via the ``get()`` method. Need not include the SOA record. If
  it is, PowerDNS will not get confused. If include_disabled is given as
  true, records that are configured but should not be served to DNS
  clients must also be made available.

  Should return false if the backend does not consider itself
  authoritative for this zone. Should throw an PDNSException if an error
  occurred accessing the database. Returning true indicates that data is
  or should be available.

.. cpp:function:: bool DNSBackend::get(DNSResourceRecord &rr)

  Request a DNSResourceRecord from a query started by ``get()`` of
  ``list()``. If this functions returns **true**, **rr** has been filled
  with data. When it returns false, no more data is available, and **rr**
  does not contain new data. A backend should make sure that it either
  fills out all fields of the DNSResourceRecord or resets them to their
  default values.

  The qname field of the DNSResourceRecord should be filled out with the
  exact ``qdomain`` passed to lookup, preserving its case. So if a query
  for 'CaSe.yourdomain.com' comes in and your database contains data for
  'case.yourdomain.com', the qname field of rr should contain
  'CaSe.yourdomain.com'!

  Should throw an PDNSException in case a database error occurred.

.. cpp:function:: bool DNSBackend::getSOA(const string &name, SOAData &soadata)

  If the backend considers itself authoritative over domain ``name``, this
  method should fill out the passed **SOAData** structure and return a
  positive number. If the backend is functioning correctly, but does not
  consider itself authoritative, it should return 0. In case of errors, an
  PDNSException should be thrown.

Reporting errors
----------------

To report errors, the Logger class is available which works mostly like
an iostream. Example usage is as shown above in the RandomBackend. Note
that it is very important that each line is ended with **endl** as your
message won't be visible otherwise.

To indicate the importance of an error, the standard syslog errorlevels
are available. They can be set by outputting ``Logger::Critical``,
``Logger::Error``, ``Logger::Warning``, ``Logger::Notice``,
``Logger::Info`` or ``Logger::Debug`` to ``L``, in descending order of
graveness.

Declaring and reading configuration details
-------------------------------------------

It is highly likely that a backend needs configuration details. On
launch, these parameters need to be declared with PowerDNS so it knows
it should accept them in the configuration file and on the command line.
Furthermore, they will be listed in the output of ``--help``.

Declaring arguments is done by implementing the member function
``declareArguments()`` in the factory class of your backend. PowerDNS
will call this method after launching the backend.

In the ``declareArguments()`` method, the function ``declare()`` is
available. The exact definitions:

.. cpp:function:: void DNSBackend::declareArguments(const string &suffix="")

  This method is called to allow a backend to register configurable
  parameters. The suffix is the sub-name of this module. There is no need
  to touch this suffix, just pass it on to the declare method.

.. cpp:function:: void DNSBackend::declare(const string &suffix, const string &param, const string &explanation, const string &value)

  The suffix is passed to your method, and can be passed on to declare.
  **param** is the name of your parameter. **explanation** is what will
  appear in the output of --help. Furthermore, a default value can be
  supplied in the **value** parameter.

  A sample implementation:

  .. code-block:: cpp

      void declareArguments(const string &suffix)
      {
        declare(suffix,"dbname","Pdns backend database name to connect to","powerdns");
        declare(suffix,"user","Pdns backend user to connect as","powerdns");
        declare(suffix,"host","Pdns backend host to connect to","");
        declare(suffix,"password","Pdns backend password to connect with","");
      }

  After the arguments have been declared, they can be accessed from your
  backend using the ``mustDo()``, ``getArg()`` and ``getArgAsNum()``
  methods. The are defined as follows in the DNSBackend class:

.. cpp:function:: void DNSBackend::setArgPrefix(const string &prefix)

  Must be called before any of the other accessing functions are used.
  Typical usage is '``setArgPrefix("mybackend"+suffix)``' in the
  constructor of a backend.

.. cpp:function:: bool DNSBackend::mustDo(const string &key)

  Returns true if the variable ``key`` is set to anything but 'no'.

.. cpp:function:: const string& DNSBackend::getArg(const string &key)

  Returns the exact value of a parameter.

.. cpp:function:: int DNSBackend::getArgAsNum(const string &key)

  Returns the numerical value of a parameter. Uses ``atoi()`` internally

  Sample usage from the BIND backend: getting the 'check-interval' setting:

  .. code-block:: cpp

      if(!safeGetBBDomainInfo(i->name, &bbd)) {
        bbd.d_id=domain_id++;
        bbd.setCheckInterval(getArgAsNum("check-interval"));
        bbd.d_lastnotified=0;
        bbd.d_loaded=false;
      }


.. _rw-slave:

Read/write slave-capable backends
---------------------------------

The backends above are 'natively capable' in that they contain all data
relevant for a domain and do not pull in data from other nameservers. To
enable storage of information, a backend must be able to do more.

Before diving into the details of the implementation some theory is in
order. Slave domains are pulled from the master. PowerDNS needs to know
for which domains it is to be a slave, and for each slave domain, what
the IP address of the master is.

A slave zone is pulled from a master, after which it is 'fresh', but
this is only temporary. In the SOA record of a zone there is a field
which specifies the 'refresh' interval. After that interval has elapsed,
the slave nameserver needs to check at the master ff the serial number
there is higher than what is stored in the backend locally.

If this is the case, PowerDNS dubs the domain 'stale', and schedules a
transfer of data from the remote. This transfer remains scheduled until
the serial numbers remote and locally are identical again.

This theory is implemented by the ``getUnfreshSlaveInfos`` method, which
is called on all backends periodically. This method fills a vector of
**SlaveDomain**\ s with domains that are unfresh and possibly stale.

PowerDNS then retrieves the SOA of those domains remotely and locally
and creates a list of stale domains. For each of these domains, PowerDNS
starts a zone transfer to resynchronise. Because zone transfers can
fail, it is important that the interface to the backend allows for
transaction semantics because a zone might otherwise be left in a
halfway updated situation.

The following excerpt from the DNSBackend shows the relevant functions:

.. code-block:: cpp

          class DNSBackend {
          public:
               /* ... */
               virtual bool getDomainInfo(const string &domain, DomainInfo &di);
           virtual bool isMaster(const string &name, const string &ip);
           virtual bool startTransaction(const string &qname, int id);
           virtual bool commitTransaction();
           virtual bool abortTransaction();
           virtual bool feedRecord(const DNSResourceRecord &rr, string *ordername=0);
           virtual void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
           virtual void setFresh(uint32_t id);
               /* ... */
         }

The mentioned DomainInfo struct looks like this:

.. cpp:class:: DomainInfo

.. cpp:member:: uint32_t DomainInfo::id

  ID of this zone within this backend

.. cpp:member:: string DomainInfo::master

  IP address of the master of this domain, if any

.. cpp:member:: uint32_t DomainInfo::serial

  Serial number of this zone

.. cpp:member:: uint32_t DomainInfo::notified_serial

  Last serial number of this zone that slaves have seen

.. cpp:member:: time_t DomainInfo::last_check

  Last time this zone was checked over at the master for changes

.. cpp:member:: enum DomainKind DomainInfo::kind

  Type of zone

.. cpp:member:: DNSBackend* DomainInfo::backend

  Pointer to the backend that feels authoritative for a domain and can act as a slave

.. cpp:enum:: DomainKind

  The kind of domain, one of {Master,Slave,Native}.

These functions all have a default implementation that returns false -
which explains that these methods can be omitted in simple backends.
Furthermore, unlike with simple backends, a slave capable backend must
make sure that the 'DNSBackend \*db' field of the SOAData record is
filled out correctly - it is used to determine which backend will house
this zone.

.. cpp:function:: bool DomainInfo::isMaster(const string &name, const string &ip)

  If a backend considers itself a slave for the domain **name** and if the
  IP address in **ip** is indeed a master, it should return true. False
  otherwise. This is a first line of checks to guard against reloading a
  domain unnecessarily.

.. cpp:function:: void DomainInfo::getUnfreshSlaveInfos(vector\<DomainInfo\>* domains)

  When called, the backend should examine its list of slave domains and
  add any unfresh ones to the domains vector.

.. cpp:function:: bool DomainInfo::getDomainInfo(const string &name, DomainInfo & di)

  This is like ``getUnfreshSlaveInfos``, but for a specific domain. If the
  backend considers itself authoritative for the named zone, ``di`` should
  be filled out, and 'true' be returned. Otherwise return false.

.. cpp:function:: bool DomainInfo::startTransaction(const string &qname, int id)

  When called, the backend should start a transaction that can be
  committed or rolled back atomically later on. In SQL terms, this
  function should **BEGIN** a transaction and **DELETE** all records.

.. cpp:function:: bool DomainInfo::feedRecord(const DNSResourceRecord &rr, string *ordername)

  Insert this record.

.. cpp:function:: bool DomainInfo::commitTransaction()

  Make the changes effective. In SQL terms, execute **COMMIT**.

.. cpp:function:: bool DomainInfo::abortTransaction()

  Abort changes. In SQL terms, execute **ABORT**.

.. cpp:function:: bool DomainInfo::setFresh()

  Indicate that a domain has either been updated or refreshed without the
  need for a retransfer. This causes the domain to vanish from the vector
  modified by ``getUnfreshSlaveInfos()``.

PowerDNS will always call ``startTransaction()`` before making calls to
``feedRecord()``. Although it is likely that ``abortTransaction()`` will
be called in case of problems, backends should also be prepared to abort
from their destructor.

The actual code in PowerDNS is currently:

.. code-block:: cpp

        Resolver resolver;
        resolver.axfr(remote,domain.c_str());

        db->startTransaction(domain, domain_id);
        g_log<<Logger::Error<<"AXFR started for '"<<domain<<"'"<<endl;
        Resolver::res_t recs;

        while(resolver.axfrChunk(recs)) {
          for(Resolver::res_t::const_iterator i=recs.begin();i!=recs.end();++i) {
        db->feedRecord(*i);
          }
        }
        db->commitTransaction();
        db->setFresh(domain_id);
        g_log<<Logger::Error<<"AXFR done for '"<<domain<<"'"<<endl;

Supermaster/Superslave capability
---------------------------------

A backend that wants to act as a 'superslave' for a master should
implement the following method:

.. code-block:: cpp

                class DNSBackend
                {
                   virtual bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **db)
                };

This function gets called with the IP address of the potential
supermaster, the domain it is sending a notification for and the set of
NS records for this domain at that IP address.

Using the supplied data, the backend needs to determine if this is a
bonafide 'supernotification' which should be honoured. If it decides
that it should, the supplied pointer to 'account' needs to be filled
with the configured name of the supermaster (if accounting is desired),
and the db needs to be filled with a pointer to your backend.

Supermaster/superslave is a complicated concept, if this is all unclear
see the :ref:`Supermaster and Superslave <supermaster-operation>`
documentation.

Read/write master-capable backends
----------------------------------

In order to be a useful master for a domain, notifies must be sent out
whenever a domain is changed. Periodically, PowerDNS queries backends
for domains that may have changed, and sends out notifications for slave
nameservers.

In order to do so, PowerDNS calls the ``getUpdatedMasters()`` method.
Like the ``getUnfreshSlaveInfos()`` function mentioned above, this
should add changed domain names to the vector passed.

The following excerpt from the DNSBackend shows the relevant functions:

.. code-block:: cpp

          class DNSBackend {
          public:
               /* ... */
           virtual void getUpdatedMasters(vector<DomainInfo>* domains);
           virtual void setNotified(uint32_t id, uint32_t serial);
               /* ... */
         }

These functions all have a default implementation that returns false -
which explains that these methods can be omitted in simple backends.
Furthermore, unlike with simple backends, a slave capable backend must
make sure that the 'DNSBackend \*db' field of the SOAData record is
filled out correctly - it is used to determine which backend will house
this zone.

.. cpp:function:: void DNSBackend::getUpdatedMasters(vector<DomainInfo>* domains)

  When called, the backend should examine its list of master domains and
  add any changed ones to the :cpp:class:`DomainInfo` vector.

.. cpp:function:: bool DNSBackend::setNotified(uint32_t domain_id, uint32_t serial)

  Indicate that notifications have been queued for this domain and that it
  need not be considered 'updated' anymore

DNS update support
------------------

To make your backend DNS update compatible, it needs to implement a
number of new functions and functions already used for slave-operation.
The new functions are not DNS update specific and might be used for
other update/remove functionality at a later stage.

.. code-block:: cpp

    class DNSBackend {
    public:
      /* ... */
      virtual bool startTransaction(const string &qname, int id);
      virtual bool commitTransaction();
      virtual bool abortTransaction();
      virtual bool feedRecord(const DNSResourceRecord &rr, string *ordername);
      virtual bool replaceRRSet(uint32_t domain_id, const string& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
      virtual bool listSubZone(const string &zone, int domain_id);
      /* ... */
    }

.. cpp:function:: virtual bool DNSBackend::startTransaction(const string &qname, int id)

  See :cpp:func:`above <DNSBackend::beginTransaction>`. Please
  note that this function now receives a negative number (-1), which
  indicates that the current zone data should NOT be deleted.

.. cpp:function:: virtual bool DNSBackend::commitTransaction()

  See :cpp:func:`above <DNSBackend::commitTransaction>`.

.. cpp:function:: virtual bool DNSBackend::abortTransaction()

  See cpp:func:`above <DNSBackend::abortTransaction>`. Method is called when an
  exception is received.

.. cpp:function:: virtual bool DNSBackend::feedRecord(const DNSResourceRecord &rr, string *ordername)

  See :cpp:func:`above <DNSBackend::feedRecord>`.
  Please keep in mind that the zone is not empty because
  ``startTransaction()`` was called different.

.. cpp:function:: virtual bool DNSBackend::listSubZone(const string &name, int domain_id)

  This method is needed for rectification of a zone after NS-records have
  been added. For DNSSEC, we need to know which records are below the
  currently added record. ``listSubZone()`` is used like ``list()`` which
  means PowerDNS will call ``get()`` after this method. The default SQL
  query looks something like this::

    // First %s is 'sub.zone.com', second %s is '*.sub.zone.com'
    select content,ttl,prio,type,domain_id,name from records where (name='%s' OR name like '%s') and domain_id=%d

  The method is not only used when adding records, but also to correct
  ENT-records in powerdns. Make sure it returns every record in the tree
  below the given record.

.. cpp:function:: virtual bool DNSBackend::replaceRRSet(uint32_t domain_id, const string& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)

  This method should remove all the records with ``qname`` of type ``qt``.
  ``qt`` might also be ANY, which means all the records with that
  ``qname`` need to be removed. After removal, the records in ``rrset``
  must be added to the zone. ``rrset`` can be empty in which case the
  method is used to remove a RRset.

Miscellaneous
-------------

ENT (Empty Non-Terminal)
~~~~~~~~~~~~~~~~~~~~~~~~

You are expected to reply with a DNSResourceRecord having ``qtype = 0``,
``ttl = 0`` and ``content`` should be empty string (string length 0)
