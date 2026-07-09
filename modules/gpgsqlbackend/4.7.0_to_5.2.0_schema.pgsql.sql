CREATE TABLE networks (
  network               CIDR NOT NULL,
  view                  VARCHAR(255) NOT NULL,
  PRIMARY KEY(network)
);


CREATE TABLE views (
  view                  VARCHAR(255) NOT NULL,
  zone                  VARCHAR(255) NOT NULL,
  variant               VARCHAR(255) NOT NULL,
  PRIMARY KEY(view, zone)
);

CREATE INDEX views_view_idx ON views(view);
