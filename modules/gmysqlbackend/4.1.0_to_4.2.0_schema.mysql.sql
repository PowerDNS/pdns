ALTER TABLE domains MODIFY notified_serial INT UNSIGNED DEFAULT NULL;

ALTER TABLE records DROP COLUMN change_date;
