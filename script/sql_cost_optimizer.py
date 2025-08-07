#!/usr/bin/env python3
"""
Snowflake SQL Cost Optimization Scanner
Detects common anti-patterns that increase Snowflake costs and optionally fixes them.
"""

import os
import re
import argparse
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class SQLIssue:
    """Represents a detected SQL anti-pattern issue"""
    file_path: str
    line_number: int
    issue_type: str
    severity: str  # HIGH, MEDIUM, LOW
    description: str
    original_line: str
    suggested_fix: Optional[str] = None
    estimated_cost_impact: str = ""

class SQLCostOptimizer:
    """Main class for detecting and fixing SQL cost anti-patterns"""
    
    def __init__(self):
        self.issues: List[SQLIssue] = []
        self.patterns = self._initialize_patterns()
        self.stats = {
            'files_scanned': 0,
            'issues_found': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0
        }
    
    def _initialize_patterns(self) -> Dict:
        """Initialize regex patterns for detecting anti-patterns"""
        return {
            'select_star': {
                'pattern': r'\bSELECT\s+\*\b',
                'severity': 'HIGH',
                'description': 'SELECT * queries scan unnecessary columns',
                'cost_impact': '300-500% increased I/O costs',
                'fix_template': '-- SELECT * replaced with specific columns\nSELECT \n    column1,\n    column2,\n    column3\nFROM {table}'
            },
            'missing_where_large_table': {
                'pattern': r'\bFROM\s+(\w+\.)?(transactions|accounts|customers|orders|payments|audit_log|events)\b(?!.*\bWHERE\b)',
                'severity': 'HIGH',
                'description': 'Query on large table without WHERE clause',
                'cost_impact': 'Full table scan - extremely expensive',
                'fix_template': '-- Add WHERE clause to filter data\n-- WHERE created_date >= DATEADD(day, -30, CURRENT_DATE())'
            },
            'unnecessary_distinct': {
                'pattern': r'\bSELECT\s+DISTINCT\b(?!.*\bGROUP\s+BY\b)',
                'severity': 'MEDIUM',
                'description': 'DISTINCT without GROUP BY causes expensive deduplication',
                'cost_impact': '50-200% increased processing time',
                'fix_template': '-- Consider using GROUP BY instead of DISTINCT for aggregations'
            },
            'order_without_limit': {
                'pattern': r'\bORDER\s+BY\b(?!.*\bLIMIT\b)(?!.*\bTOP\b)',
                'severity': 'MEDIUM',
                'description': 'ORDER BY without LIMIT sorts entire result set',
                'cost_impact': 'Unnecessary sorting of large datasets',
                'fix_template': '-- Add LIMIT to ORDER BY\n-- ORDER BY column_name LIMIT 1000'
            },
            'union_instead_union_all': {
                'pattern': r'\bUNION\s+(?!ALL\b)',
                'severity': 'MEDIUM',
                'description': 'UNION performs unnecessary deduplication',
                'cost_impact': '20-100% increased processing time',
                'fix_template': '-- Use UNION ALL if duplicates are acceptable\nUNION ALL'
            },
            'create_drop_table': {
                'pattern': r'\b(CREATE\s+(OR\s+REPLACE\s+)?TABLE|DROP\s+TABLE)\b',
                'severity': 'HIGH',
                'description': 'Creating/dropping tables in ETL causes metadata overhead',
                'cost_impact': 'Time Travel storage costs + performance degradation',
                'fix_template': '-- Use permanent staging tables with TRUNCATE instead\n-- TRUNCATE TABLE staging.temp_table;'
            },
            'create_function_procedure': {
                'pattern': r'\bCREATE\s+(OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE)\b',
                'severity': 'HIGH',
                'description': 'Creating functions/procedures in ETL causes compilation overhead',
                'cost_impact': 'Metadata bloat + compilation time on every run',
                'fix_template': '-- Deploy functions during release, not in ETL\n-- Use inline SQL logic instead'
            },
            'varchar_without_size': {
                'pattern': r'\bVARCHAR\s*(?!\s*\(\s*\d+\s*\))',
                'severity': 'LOW',
                'description': 'VARCHAR without size limit wastes storage',
                'cost_impact': 'Higher storage costs',
                'fix_template': '-- Specify appropriate VARCHAR size\nVARCHAR(100)  -- Adjust size as needed'
            },
            'nested_subqueries': {
                'pattern': r'\(\s*SELECT.*\(\s*SELECT.*FROM.*\).*FROM.*\)',
                'severity': 'MEDIUM',
                'description': 'Deeply nested subqueries hurt performance',
                'cost_impact': 'Poor query optimization',
                'fix_template': '-- Use CTEs (WITH clauses) for better readability and performance\nWITH subquery1 AS (\n    SELECT ...\n)'
            },
            'cursor_usage': {
                'pattern': r'\b(DECLARE.*CURSOR|FOR.*CURSOR|OPEN\s+CURSOR|FETCH\s+FROM)\b',
                'severity': 'HIGH',
                'description': 'Cursor-based row-by-row processing is extremely inefficient',
                'cost_impact': 'Thousands of times slower than set-based operations',
                'fix_template': '-- Use set-based operations instead\n-- MERGE, INSERT, UPDATE with JOINs'
            },
            'multiple_single_inserts': {
                'pattern': r'INSERT\s+INTO.*VALUES\s*\([^)]*\)\s*;.*INSERT\s+INTO',
                'severity': 'MEDIUM',
                'description': 'Multiple single INSERT statements are inefficient',
                'cost_impact': 'Multiple small transactions vs efficient batching',
                'fix_template': '-- Use bulk INSERT or multi-value INSERT\nINSERT INTO table VALUES (val1), (val2), (val3);'
            }
        }
    
    def scan_directory(self, etl_path: str) -> None:
        """Scan ETL directory for SQL files and detect issues"""
        etl_directory = Path(etl_path)
        
        if not etl_directory.exists():
            raise FileNotFoundError(f"ETL directory not found: {etl_path}")
        
        # Recursively find all .sql files
        sql_files = list(etl_directory.rglob("*.sql"))
        
        print(f"Found {len(sql_files)} SQL files to scan...")
        
        for sql_file in sql_files:
            self._scan_sql_file(str(sql_file))
        
        self._generate_summary()
    
    def _scan_sql_file(self, file_path: str) -> None:
        """Scan individual SQL file for anti-patterns"""
        self.stats['files_scanned'] += 1
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return
        
        # Check each pattern against the entire file content
        for pattern_name, pattern_info in self.patterns.items():
            matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            
            for match in matches:
                # Find line number where match occurs
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                
                # Skip if this is in a comment
                if self._is_in_comment(content, match.start()):
                    continue
                
                issue = SQLIssue(
                    file_path=file_path,
                    line_number=line_num,
                    issue_type=pattern_name,
                    severity=pattern_info['severity'],
                    description=pattern_info['description'],
                    original_line=line_content,
                    suggested_fix=pattern_info['fix_template'],
                    estimated_cost_impact=pattern_info['cost_impact']
                )
                
                self.issues.append(issue)
                self.stats['issues_found'] += 1
                self.stats[f"{pattern_info['severity'].lower()}_severity"] += 1
    
    def _is_in_comment(self, content: str, position: int) -> bool:
        """Check if position is within a SQL comment"""
        # Check for single-line comment
        line_start = content.rfind('\n', 0, position) + 1
        line_content = content[line_start:content.find('\n', position)]
        if '--' in line_content and line_content.find('--') < (position - line_start):
            return True
        
        # Check for multi-line comment
        comment_start = content.rfind('/*', 0, position)
        comment_end = content.find('*/', comment_start)
        if comment_start != -1 and (comment_end == -1 or comment_end > position):
            return True
        
        return False
    
    def _generate_summary(self) -> None:
        """Generate scanning summary"""
        print(f"\n📊 Scan Summary:")
        print(f"Files scanned: {self.stats['files_scanned']}")
        print(f"Total issues: {self.stats['issues_found']}")
        print(f"High severity: {self.stats['high_severity']}")
        print(f"Medium severity: {self.stats['medium_severity']}")
        print(f"Low severity: {self.stats['low_severity']}")
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate detailed report of all issues found"""
        if not self.issues:
            return "No issues found!"
        
        # Group issues by file
        issues_by_file = {}
        for issue in self.issues:
            if issue.file_path not in issues_by_file:
                issues_by_file[issue.file_path] = []
            issues_by_file[issue.file_path].append(issue)
        
        report = []
        report.append("# Snowflake SQL Cost Optimization Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total files scanned: {self.stats['files_scanned']}")
        report.append(f"Total issues found: {self.stats['issues_found']}")
        report.append("")
        
        # Summary by severity
        report.append("## Issues by Severity")
        report.append(f"- 🔴 High: {self.stats['high_severity']} issues")
        report.append(f"- 🟡 Medium: {self.stats['medium_severity']} issues")
        report.append(f"- 🟢 Low: {self.stats['low_severity']} issues")
        report.append("")
        
        # Issues by type
        issue_types = {}
        for issue in self.issues:
            issue_types[issue.issue_type] = issue_types.get(issue.issue_type, 0) + 1
        
        report.append("## Issues by Type")
        for issue_type, count in sorted(issue_types.items(), key=lambda x: x[1], reverse=True):
            report.append(f"- {issue_type}: {count} occurrences")
        report.append("")
        
        # Detailed issues by file
        report.append("## Detailed Issues by File")
        for file_path, file_issues in sorted(issues_by_file.items()):
            relative_path = file_path.replace(os.getcwd(), '.')
            report.append(f"### {relative_path}")
            
            for issue in sorted(file_issues, key=lambda x: x.line_number):
                severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}[issue.severity]
                report.append(f"")
                report.append(f"**Line {issue.line_number}** {severity_icon} {issue.severity}")
                report.append(f"- **Issue**: {issue.description}")
                report.append(f"- **Cost Impact**: {issue.estimated_cost_impact}")
                report.append(f"- **Current Code**: `{issue.original_line}`")
                if issue.suggested_fix:
                    report.append(f"- **Suggested Fix**:")
                    report.append(f"```sql")
                    report.append(issue.suggested_fix)
                    report.append(f"```")
                report.append("")
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"Report saved to: {output_file}")
        
        return report_text
    
    def fix_issues_in_place(self, dry_run: bool = True) -> None:
        """Fix issues in place by commenting original and adding optimized version"""
        if not self.issues:
            print("No issues to fix!")
            return
        
        # Group issues by file
        issues_by_file = {}
        for issue in self.issues:
            if issue.file_path not in issues_by_file:
                issues_by_file[issue.file_path] = []
            issues_by_file[issue.file_path].append(issue)
        
        for file_path, file_issues in issues_by_file.items():
            if dry_run:
                print(f"\n🔍 Would fix {len(file_issues)} issues in: {file_path}")
                continue
            
            self._fix_file_issues(file_path, file_issues)
    
    def _fix_file_issues(self, file_path: str, issues: List[SQLIssue]) -> None:
        """Fix issues in a specific file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return
        
        # Sort issues by line number in reverse order to avoid index shifting
        issues.sort(key=lambda x: x.line_number, reverse=True)
        
        for issue in issues:
            line_idx = issue.line_number - 1
            if line_idx >= len(lines):
                continue
            
            original_line = lines[line_idx]
            
            # Create fix comment and suggestion
            fix_comment = f"-- COST OPTIMIZATION FIX: {issue.description}\n"
            fix_comment += f"-- Original line commented below, optimized version added\n"
            fix_comment += f"-- Cost Impact: {issue.estimated_cost_impact}\n"
            
            commented_original = f"-- ORIGINAL: {original_line}"
            if not original_line.endswith('\n'):
                commented_original += '\n'
            
            # Add suggested fix if available
            suggested_fix = ""
            if issue.suggested_fix and not issue.suggested_fix.startswith('--'):
                suggested_fix = issue.suggested_fix + '\n'
            
            # Replace the line
            replacement = fix_comment + commented_original + suggested_fix
            lines[line_idx] = replacement
        
        # Write back to file
        try:
            # Create backup
            backup_path = f"{file_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(''.join(lines))
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            print(f"✅ Fixed {len(issues)} issues in {file_path}")
            print(f"   Backup created: {backup_path}")
            
        except Exception as e:
            print(f"Error writing fixes to {file_path}: {e}")
    
    def export_issues_json(self, output_file: str) -> None:
        """Export issues to JSON format for further processing"""
        issues_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'issues': [asdict(issue) for issue in self.issues]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(issues_data, f, indent=2)
        
        print(f"Issues exported to JSON: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Snowflake SQL Cost Optimization Scanner")
    parser.add_argument("etl_path", help="Path to ETL directory containing SQL files")
    parser.add_argument("--report", "-r", help="Output file for detailed report")
    parser.add_argument("--json", "-j", help="Output file for JSON export")
    parser.add_argument("--fix", action="store_true", help="Fix issues in place (creates backups)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be fixed without making changes")
    
    args = parser.parse_args()
    
    optimizer = SQLCostOptimizer()
    
    print(f"🔍 Scanning ETL directory: {args.etl_path}")
    optimizer.scan_directory(args.etl_path)
    
    if args.report:
        optimizer.generate_report(args.report)
    else:
        print("\n" + optimizer.generate_report())
    
    if args.json:
        optimizer.export_issues_json(args.json)
    
    if args.fix or args.dry_run:
        optimizer.fix_issues_in_place(dry_run=args.dry_run)
    
    if optimizer.stats['issues_found'] > 0:
        print(f"\n💡 Found {optimizer.stats['issues_found']} optimization opportunities!")
        print("   Run with --fix to apply fixes (backups will be created)")
    else:
        print("\n✅ No cost optimization issues found!")

if __name__ == "__main__":
    main()
