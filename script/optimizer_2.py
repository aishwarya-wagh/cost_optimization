#!/usr/bin/env python3

import os
import re
import shutil
from pathlib import Path
import argparse

class SqlOptimizer:
    def __init__(self):
        self.results = []
        
    def scan_files(self, etl_dir):
        sql_files = []
        for root, dirs, files in os.walk(etl_dir):
            for file in files:
                if file.endswith('.sql'):
                    sql_files.append(os.path.join(root, file))
        
        print(f"Found {len(sql_files)} SQL files")
        
        for file_path in sql_files:
            issues = self.check_file(file_path)
            if issues:
                self.results.append({
                    'file': file_path,
                    'issues': issues
                })
        
        return self.results
    
    def check_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                content = f.read()
        except:
            return []
        
        issues = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_upper = line.upper().strip()
            
            # Skip comments and empty lines
            if line_upper.startswith('--') or not line_upper:
                continue
                
            # Check for SELECT *
            if 'SELECT *' in line_upper:
                issues.append({
                    'line': i,
                    'type': 'select_star',
                    'description': 'SELECT * found - scans all columns',
                    'content': line.strip(),
                    'severity': 'HIGH'
                })
            
            # Check for large table queries without WHERE
            large_tables = ['TRANSACTIONS', 'ACCOUNTS', 'CUSTOMERS', 'ORDERS', 'PAYMENTS', 'EVENTS']
            for table in large_tables:
                if f'FROM {table}' in line_upper or f'JOIN {table}' in line_upper:
                    # Look ahead a few lines to see if there's a WHERE clause
                    has_where = False
                    for j in range(max(0, i-2), min(len(lines), i+3)):
                        if 'WHERE' in lines[j].upper():
                            has_where = True
                            break
                    
                    if not has_where:
                        issues.append({
                            'line': i,
                            'type': 'missing_where',
                            'description': f'Query on {table} without WHERE clause',
                            'content': line.strip(),
                            'severity': 'HIGH'
                        })
            
            # Check for ORDER BY without LIMIT
            if 'ORDER BY' in line_upper and 'LIMIT' not in line_upper and 'TOP' not in line_upper:
                issues.append({
                    'line': i,
                    'type': 'order_no_limit',
                    'description': 'ORDER BY without LIMIT - sorts entire result',
                    'content': line.strip(),
                    'severity': 'MEDIUM'
                })
            
            # Check for CREATE/DROP TABLE
            if 'CREATE TABLE' in line_upper or 'DROP TABLE' in line_upper:
                if 'TEMPORARY' not in line_upper and 'TEMP' not in line_upper:
                    issues.append({
                        'line': i,
                        'type': 'create_drop_table',
                        'description': 'Creating/dropping permanent tables in ETL',
                        'content': line.strip(),
                        'severity': 'HIGH'
                    })
            
            # Check for UNION without ALL
            if re.search(r'\bUNION\s+(?!ALL)', line_upper):
                issues.append({
                    'line': i,
                    'type': 'union_without_all',
                    'description': 'UNION without ALL - does unnecessary deduplication',
                    'content': line.strip(),
                    'severity': 'MEDIUM'
                })
            
            # Check for DISTINCT
            if 'SELECT DISTINCT' in line_upper:
                issues.append({
                    'line': i,
                    'type': 'distinct_usage',
                    'description': 'DISTINCT usage - consider if GROUP BY is better',
                    'content': line.strip(),
                    'severity': 'MEDIUM'
                })
        
        return issues
    
    def print_report(self):
        total_issues = sum(len(r['issues']) for r in self.results)
        print(f"\n=== Found {total_issues} issues in {len(self.results)} files ===\n")
        
        for result in self.results:
            rel_path = result['file'].replace(os.getcwd(), '.')
            print(f"FILE: {rel_path}")
            
            for issue in result['issues']:
                severity_mark = "🔴" if issue['severity'] == 'HIGH' else "🟡"
                print(f"  {severity_mark} Line {issue['line']}: {issue['description']}")
                print(f"     Code: {issue['content']}")
            print()
    
    def fix_files(self, backup_dir='backup'):
        if not self.results:
            print("No issues to fix")
            return
        
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        for result in self.results:
            file_path = result['file']
            issues = result['issues']
            
            # Create backup
            backup_name = os.path.basename(file_path) + '.bak'
            backup_path = os.path.join(backup_dir, backup_name)
            shutil.copy2(file_path, backup_path)
            
            # Fix the file
            self.fix_single_file(file_path, issues)
            print(f"Fixed {file_path} (backup: {backup_path})")
    
    def fix_single_file(self, file_path, issues):
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Apply fixes
        fixed_content = content
        
        # Fix SELECT * (simple approach)
        fixed_content = re.sub(
            r'SELECT\s+\*(?=\s+FROM)',
            'SELECT \n    -- TODO: Replace * with specific columns\n    *',
            fixed_content,
            flags=re.IGNORECASE
        )
        
        # Fix UNION to UNION ALL where it makes sense
        fixed_content = re.sub(
            r'\bUNION\s+(?!ALL)',
            'UNION ALL ',
            fixed_content,
            flags=re.IGNORECASE
        )
        
        # Add LIMIT to ORDER BY (conservative approach)
        def add_limit_to_order(match):
            order_clause = match.group(0)
            if ';' in order_clause:
                return order_clause.replace(';', ' LIMIT 1000;')
            else:
                return order_clause + ' LIMIT 1000'
        
        fixed_content = re.sub(
            r'ORDER\s+BY\s+[^;]*(?=;|\s*$)',
            add_limit_to_order,
            fixed_content,
            flags=re.IGNORECASE
        )
        
        # Replace CREATE TABLE with CREATE OR REPLACE TRANSIENT TABLE for temp tables
        pattern = r'CREATE\s+TABLE\s+(?!.*TRANSIENT)(?=\w+\.(temp_|tmp_|staging_))'
        fixed_content = re.sub(
            pattern,
            'CREATE OR REPLACE TRANSIENT TABLE ',
            fixed_content,
            flags=re.IGNORECASE
        )
        
        with open(file_path, 'w') as f:
            f.write(fixed_content)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('etl_path', help='Path to ETL directory')
    parser.add_argument('--fix', action='store_true', help='Apply fixes to files')
    parser.add_argument('--backup-dir', default='sql_backup', help='Backup directory')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.etl_path):
        print(f"Directory {args.etl_path} not found")
        return
    
    optimizer = SqlOptimizer()
    results = optimizer.scan_files(args.etl_path)
    
    if results:
        optimizer.print_report()
        
        if args.fix:
            response = input("\nApply fixes? This will modify files (y/N): ")
            if response.lower().startswith('y'):
                optimizer.fix_files(args.backup_dir)
                print(f"\nFiles fixed. Backups stored in {args.backup_dir}/")
            else:
                print("No changes made")
    else:
        print("No issues found!")

if __name__ == "__main__":
    main()
