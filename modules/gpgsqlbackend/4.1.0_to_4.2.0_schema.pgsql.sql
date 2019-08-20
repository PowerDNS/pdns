ALTER TABLE records DROP COLUMN change_date;
ALTER TABLE domains ALTER notified_serial TYPE bigint USING CASE WHEN notified_serial >= 0 THEN notified_serial::bigint END;
