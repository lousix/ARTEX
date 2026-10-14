package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Autumn-27/artex/hybrid"
)

// Assessment lives on the origin fact so task archive/restore and inheritance
// preserve the configuration without adding an untracked side table. It contains
// only paths and identity labels; never login output or credentials.
func (s *ExplorationStore) Assessment() (*hybrid.Config, error) {
	if s == nil {
		return nil, nil
	}
	var raw []byte
	err := s.db.QueryRow(`SELECT payload->'assessment' FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state='origin' ORDER BY id LIMIT 1`, s.expID).Scan(&raw)
	if err == sql.ErrNoRows || (err == nil && (len(raw) == 0 || string(raw) == "null")) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg hybrid.Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Commit the hypothesis and its producing intent edge together, using the same
// deletion/archive evidence lock as findings.
func (s *ExplorationStore) RecordCodeHypothesis(ctx context.Context, taskID, intentID int64, payload map[string]any) (id int64, err error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	err = s.db.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		var owned bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM tasks t JOIN exploration_nodes n ON n.exploration_id=t.exploration_id WHERE t.id=$1 AND t.exploration_id=$2 AND n.id=$3 AND n.kind='intent')`, taskID, s.expID, intentID).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return errors.New("候选问题必须属于当前任务的意图")
		}
		if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin) VALUES($1,'fact',$2,7,'confirmed','codeworker') RETURNING id`, s.expID, string(raw)).Scan(&id); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,'yields',$3)`, s.expID, intentID, id)
		return err
	})
	return id, err
}
