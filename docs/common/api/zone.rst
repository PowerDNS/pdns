RRSet
-----

.. json:object:: RRSet

  This represents a Resource Record set (all record with the same name and type).

  :property string name: Name for record set (e.g. "www.powerdns.com.")
  :property string type: Type of this record (e.g. "A", "PTR", "MX")
  :property integer ttl: DNS TTL of the records, in seconds. MUST NOT be included when ``changetype`` is set to "DELETE".
  :property string changetype: MUST be added when updating the RRSet. Must be ``REPLACE`` or ``DELETE``. With ``DELETE``, all existing RRs matching ``name`` and ``type`` will be deleted,  including all comments. With ``REPLACE``: when ``records`` is present, all existing RRs matching ``name`` and ``type`` will be deleted, and then new records given in ``records`` will be created. If no records are left, any existing comments will be deleted as well. When ``comments`` is present, all existing comments for the RRs matching ``name`` and ``type`` will be deleted, and then new comments given in ``comments`` will be created.
  :property [RREntry] records: All records in this RRSet. When updating records, this is the list of new records (replacing the old ones). Must be empty when ``changetype`` is set to ``DELETE``. An empty list results in deletion of all records (and comments).
  :property [Comment] comments: List of :json:object:`Comment`. Must be empty when ``changetype`` is set to ``DELETE``. An empty list results in deletion of all comments. ``modified_at`` is optional and defaults to the current server time.

RREntry
-------

.. json:object:: RREntry

  The RREntry object represents a single record in an :json:object:`RRSet`.

  :property string content: The content of this record
  :property bool disabled: Whether or not this record is disabled
  :property bool set-ptr: If set to true, the server will find the matching reverse zone and create a PTR there. Existing PTR records are replaced. If no matching reverse :json:object:`Zone`, an error is thrown. Only valid in client bodies, only valid for A and AAAA types. Not returned by the server. This feature (set-ptr) is deprecated and will be removed in 4.3.0.


Comment
-------

.. json:object:: Comment

  :property string content: The actual comment
  :property string account: Name of an account that added the comment
  :property integer modified_at: Timestamp of the last change to the comment
