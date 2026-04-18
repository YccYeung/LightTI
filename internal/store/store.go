package store

import (
	"fmt"
	"context"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store abstracts the database layer so the rest of the app is not coupled to Postgres directly.
type Store interface {
	SaveLookup(ctx context.Context, ioc string, iocType string) (uuid.UUID, error)
	SaveResult(ctx context.Context, lookupID uuid.UUID, source string, result []byte, err string) error
	GetRecentLookup(ctx context.Context, ioc string, iocType string) (uuid.UUID, error)
	GetRecentResult(ctx context.Context, lookupID uuid.UUID) ([][]byte, error)
}

// Postgres implements Store using a pgxpool connection pool.
type Postgres struct {
	pool *pgxpool.Pool
}

// New creates a pgxpool connection pool and returns a Postgres store.
func New(ctx context.Context, dbURL string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

// SaveLookup inserts an IOC record and returns the generated UUID, used to link enrichment results.
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

// GetRecentLookup returns the UUID of the most recent lookup for an IOC within the last 24 hours.
// Used to serve cached results without hitting external APIs again.
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
		if err := rows.Scan(&result); err != nil {
			fmt.Fprintf(os.Stderr, "failed to scan row: %v\n", err)
    		continue
		}
		allResult = append(allResult, result)
	}
	
	return allResult, nil
}