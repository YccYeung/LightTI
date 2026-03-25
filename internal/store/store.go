package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store interface {
	SaveLookup(ctx context.Context, ioc string, iocType string) (uuid.UUID, error)
	SaveResult(ctx context.Context, lookupID uuid.UUID, source string, result []byte, err string) error
	GetRecentLookup(ctx context.Context, ioc string, iocType string) (uuid.UUID, error)
	GetRecentResult(ctx context.Context, lookupID uuid.UUID) ([][]byte, error)
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

func (p *Postgres) GetRecentLookup(ctx context.Context, ioc string, iocType string) (uuid.UUID, error) {
	var id uuid.UUID 
	query := "SELECT id FROM lookups WHERE ioc = $1 AND ioc_type = $2 " + 
			"AND created_at > now() - INTERVAL '24 hours' " +
			"ORDER BY created_at DESC " +
			"LIMIT 1"
	err := p.pool.QueryRow(ctx, query, ioc, iocType).Scan(&id)
	if err != nil {
		return uuid.UUID{}, err
	} 
	return id, nil	
}

func (p *Postgres) GetRecentResult(ctx context.Context, lookupID uuid.UUID) ([][]byte, error) {
	var allResult [][]byte
	query := "SELECT result FROM enrichment_results where lookup_id = $1"

	rows, err := p.pool.Query(ctx, query, lookupID)
	if err != nil {
		return nil, err
	}
	
	for rows.Next() {
		var result []byte
		rows.Scan(&result)
		allResult = append(allResult, result)
	}
	
	return allResult, nil
}