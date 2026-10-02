-- Runs once when the docker volume is first created.
CREATE EXTENSION IF NOT EXISTS vector;
-- Second database so pytest never touches demo data.
CREATE DATABASE security_test_db;
\connect security_test_db
CREATE EXTENSION IF NOT EXISTS vector;
