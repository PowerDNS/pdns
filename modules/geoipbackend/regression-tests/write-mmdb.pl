use MaxMind::DB::Writer::Tree;

my %types = (
    city                             => 'map',
    names                            => 'map',
    en                               => 'utf8_string',
    geoname_id                       => 'uint32',
    location                         => 'map',
    latitude                         => 'double',
    longitude                        => 'double',
    accuracy_radius                  => 'uint16',
    continent                        => 'map',
    country                          => 'map',
    code                             => 'utf8_string',
    iso_code                         => 'utf8_string',
    subdivisions                     => ['array', 'map'],
    autonomous_system_number         => 'uint32',
    autonomous_system_organization   => 'utf8_string',
    );

my $tree = MaxMind::DB::Writer::Tree->new(
    ip_version            => 6,
    record_size           => 28,
    database_type         => 'GeoCity-Lite',
    languages             => ['en'],
    description           => { en => 'Mock geoip database' },
    map_key_type_callback => sub { $types{ $_[0] } },
    remove_reserved_networks => 0,
);

$tree->insert_network(
    '1.1.1.0/24',
    {
      'city' => { "geoname_id" => 2151718, "names" => { "en" => "Research" } },
      'continent' => { "code" => "OC", "geoname_id" => 6255151, "names" => { "en" => "Oceania" } },
      'country' => { "geoname_id" => 2077456, "iso_code" => "AU", "names" => { "en" => "Australia" } },
      'location' => { "latitude" => 1.0, "longitude" => 1.0, accuracy_radius => 1 },
      'autonomous_system_number' => 4242,
      'autonomous_system_organization' => "Test Telekom",
    }
);

$tree->insert_network(
    '1.2.3.0/24',
    {
      'city' => { "geoname_id" => 5804306, "names" => { "en" => "Mukilteo" } },
      'continent' => { "code" => "NA", "geoname_id" => 6255149, "names" => { "en" => "North America" } },
      'country' => { "geoname_id" => 6252001, "iso_code" => "US", "names" => { "en" => "United States" } },
      'location' => { "latitude" => 47.913000, "longitude" => -122.304200, accuracy_radius => 1 },
      'autonomous_system_number' => 3320,
      'autonomous_system_organization' => "Test Networks",
    }
);

$tree->insert_network(
    '127.0.0.1/32',
    {
      'country' => { "geoname_id" => 1, "iso_code" => "O1", "names" => { "en" => "O 1" } },
      'city' => { "geoname_id" => 1, "names" => { "en" => "C1" } },
      'subdivisions' => [{ "geoname_id" => 1, "iso_code" => "L1", "names" => { "en" => "L 1" } }],
    }
);

$tree->insert_network(
    '127.0.0.2/32',
    {
      'country' => { "geoname_id" => 2, "iso_code" => "O1", "names" => { "en" => "O 2" } },
      'subdivisions' => [{ "geoname_id" => 2, "iso_code" => "L2", "names" => { "en" => "L 2" } }],
      'city' => { "geoname_id" => 2, "names" => { "en" => "C2" } },
    }
);

$tree->insert_network(
    '127.0.0.3/32',
    {
      'country' => { "geoname_id" => 3, "iso_code" => "O1", "names" => { "en" => "O 3" } },
      'subdivisions' => [{ "geoname_id" => 3, "iso_code" => "L3", "names" => { "en" => "L 3" } }],
      'city' => { "geoname_id" => 3, "names" => { "en" => "C3" } },
    }
);

open my $fh, '>:raw', 'GeoLiteCity.mmdb';
$tree->write_tree($fh);
