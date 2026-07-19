ALTER TABLE persons ADD COLUMN unix_username TEXT;

UPDATE persons
SET unix_username = (
    SELECT MIN(binding.unix_username)
    FROM login_bindings binding
    WHERE binding.person_id = persons.id AND binding.enabled = 1
)
WHERE 1 = (
    SELECT COUNT(DISTINCT binding.unix_username)
    FROM login_bindings binding
    WHERE binding.person_id = persons.id AND binding.enabled = 1
)
AND 1 = (
    SELECT COUNT(DISTINCT owner.person_id)
    FROM login_bindings owner
    WHERE owner.enabled = 1
      AND owner.unix_username = (
          SELECT MIN(binding.unix_username)
          FROM login_bindings binding
          WHERE binding.person_id = persons.id AND binding.enabled = 1
      )
);

DROP TABLE login_bindings;

CREATE UNIQUE INDEX person_unix_username
    ON persons(unix_username)
    WHERE unix_username IS NOT NULL;

ALTER TABLE tests ADD COLUMN question_limit INTEGER
    CHECK (question_limit IS NULL OR question_limit BETWEEN 1 AND 200);
ALTER TABLE tests ADD COLUMN shuffle_questions INTEGER NOT NULL DEFAULT 1
    CHECK (shuffle_questions IN (0, 1));
ALTER TABLE tests ADD COLUMN shuffle_choices INTEGER NOT NULL DEFAULT 1
    CHECK (shuffle_choices IN (0, 1));
