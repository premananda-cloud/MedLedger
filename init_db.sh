#!/bin/bash

# MedLedger Database Initialization Script

DB_NAME="medledger_db"
DB_USER="premananda"
SCHEMA_FILE="schema.sql"  # Changed from schema_init.sql to schema.sql

echo "MedLedger Database Initialization"
echo "======================================"

# Check if database exists, create if not
DB_EXISTS=$(psql -U $DB_USER -lqt | cut -d \| -f 1 | grep -w $DB_NAME | wc -l)

if [ $DB_EXISTS -eq 0 ]; then
    echo "Creating database: $DB_NAME"
    createdb -U $DB_USER $DB_NAME
    echo "Database created successfully."
    echo "Initializing fresh database..."
    psql -U $DB_USER -d $DB_NAME -f $SCHEMA_FILE
else
    echo "Database '$DB_NAME' already exists."
    echo "Options:"
    echo "  1) Reset database (WARNING: This will delete all data!)"
    echo "  2) Exit without changes"
    read -p "Choose option [1-2]: " option

    case $option in
        1)
            echo "Resetting database..."
            psql -U $DB_USER -d $DB_NAME -f $SCHEMA_FILE
            ;;
        2)
            echo "Exiting without changes."
            exit 0
            ;;
        *)
            echo "Invalid option. Exiting."
            exit 1
            ;;
    esac
fi

if [ $? -eq 0 ]; then
    echo "Database initialization complete!"
else
    echo "ERROR: Database initialization failed!"
    exit 1
fi
