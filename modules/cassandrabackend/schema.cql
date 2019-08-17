CREATE TABLE dns (
    domain text PRIMARY KEY,
    record list<frozen<tuple<ascii, text, int, text>>>
)

