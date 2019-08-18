CREATE TABLE dns (
    domain text PRIMARY KEY,
    records list<frozen<tuple<ascii, text, int, text>>>,
    keys list<frozen<tuple<boolean, int, text, int>>>
);
