package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store interface {
	SaveLookup(ctx context.Context, ioc string, iocType string) (uuid.UUID, error)
	SaveResult(ctx context.Context, lookupID uuid.UUID, source string, result []byte, err string) error
}

type Postgres struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dbURL string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) SaveLookup(ctx context.Context, ioc string, iocType string) (uuid.UUID, error) {
	var id uuid.UUID 
	err := p.pool.QueryRow(ctx, "INSERT INTO lookups (ioc, ioc_type) VALUES ($1, $2) RETURNING id", ioc, iocType).Scan(&id)
	if err != nil {
		return uuid.UUID{}, err
	} 
	return id, nil
}

func (p *Postgres) SaveResult(ctx context.Context, lookupID uuid.UUID, source string, result []byte, errMsg string) error {
	_, err := p.pool.Exec(ctx, "INSERT INTO enrichment_results (lookup_id, source, result, error) VALUES ($1, $2, $3, $4)", lookupID, source, result, errMsg)
	if err != nil {
		return err
	} 
	return nil
}