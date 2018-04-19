alter table zap2_records add column hash varchar(60) NULL;
CREATE INDEX record_id_idx ON zap2_domains(record_id);
CREATE INDEX record_id_idx ON zap2_only_ips(record_id);
CREATE INDEX record_id_idx ON zap2_urls(record_id);
CREATE INDEX record_id_idx ON zap2_subnets(record_id);
alter table zap2_settings drop index param, add unique key param (param);
