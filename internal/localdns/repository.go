package localdns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type Store interface {
	Create(ctx context.Context, input RecordInput) (Record, error)
	List(ctx context.Context) ([]Record, error)
	ListEnabled(ctx context.Context) ([]Record, error)
	Get(ctx context.Context, id int64) (Record, error)
	Update(ctx context.Context, id int64, input RecordInput) (Record, error)
	Delete(ctx context.Context, id int64) error
}

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(db *sql.DB) *SQLiteRepository {
	return &SQLiteRepository{db: db}
}

func (r *SQLiteRepository) Create(ctx context.Context, input RecordInput) (Record, error) {
	record, err := NewRecord(input)
	if err != nil {
		return Record{}, err
	}

	now := time.Now().UTC()
	result, err := r.db.ExecContext(ctx, `
INSERT INTO local_dns_records (
	name,
	type,
	value,
	ttl,
	enabled,
	comment,
	created_at,
	updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Name,
		string(record.Type),
		record.Value,
		record.TTL,
		boolInt(record.Enabled),
		record.Comment,
		formatTime(now),
		formatTime(now),
	)
	if err != nil {
		return Record{}, fmt.Errorf("create local dns record: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return Record{}, fmt.Errorf("read local dns record id: %w", err)
	}
	return r.Get(ctx, id)
}

func (r *SQLiteRepository) List(ctx context.Context) ([]Record, error) {
	return r.list(ctx, "")
}

func (r *SQLiteRepository) ListEnabled(ctx context.Context) ([]Record, error) {
	return r.list(ctx, "WHERE enabled = 1")
}

func (r *SQLiteRepository) list(ctx context.Context, where string) ([]Record, error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT
	id,
	name,
	type,
	value,
	ttl,
	enabled,
	comment,
	created_at,
	updated_at
FROM local_dns_records
`+where+`
ORDER BY name ASC, type ASC, value ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list local dns records: %w", err)
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list local dns records: %w", err)
	}
	if records == nil {
		return []Record{}, nil
	}
	return records, nil
}

func (r *SQLiteRepository) Get(ctx context.Context, id int64) (Record, error) {
	row := r.db.QueryRowContext(ctx, `
SELECT
	id,
	name,
	type,
	value,
	ttl,
	enabled,
	comment,
	created_at,
	updated_at
FROM local_dns_records
WHERE id = ?`, id)
	record, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

func (r *SQLiteRepository) Update(ctx context.Context, id int64, input RecordInput) (Record, error) {
	record, err := NewRecord(input)
	if err != nil {
		return Record{}, err
	}

	result, err := r.db.ExecContext(ctx, `
UPDATE local_dns_records
SET
	name = ?,
	type = ?,
	value = ?,
	ttl = ?,
	enabled = ?,
	comment = ?,
	updated_at = ?
WHERE id = ?`,
		record.Name,
		string(record.Type),
		record.Value,
		record.TTL,
		boolInt(record.Enabled),
		record.Comment,
		formatTime(time.Now().UTC()),
		id,
	)
	if err != nil {
		return Record{}, fmt.Errorf("update local dns record: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return Record{}, fmt.Errorf("check local dns record update: %w", err)
	}
	if rows == 0 {
		return Record{}, ErrNotFound
	}
	return r.Get(ctx, id)
}

func (r *SQLiteRepository) Delete(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM local_dns_records WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete local dns record: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check local dns record delete: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (Record, error) {
	var record Record
	var recordType string
	var enabled int
	var createdAt string
	var updatedAt string
	if err := row.Scan(
		&record.ID,
		&record.Name,
		&recordType,
		&record.Value,
		&record.TTL,
		&enabled,
		&record.Comment,
		&createdAt,
		&updatedAt,
	); err != nil {
		return Record{}, err
	}
	record.Type = RecordType(recordType)
	record.Enabled = enabled != 0

	var err error
	record.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return Record{}, err
	}
	record.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse local dns record time: %w", err)
	}
	return t, nil
}
