-- +goose Up
CREATE TABLE event_outbox (
	id SERIAL PRIMARY KEY,
	event_id UUID NOT NULL,
	type_event VARCHAR(50) NOT NULL,
	user_id UUID NOT NULL,
	email VARCHAR(255) NOT NULL,
	verification_url VARCHAR(255),
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL,
	status VARCHAR(50) NOT NULL DEFAULT 'pending'
		CHECK (status IN (
			'error',
			'dispatching',
			'pending'
        ))
);
