# Snowflake Developer Guidelines: Cost Optimization Best Practices
*A Comprehensive Guide to Avoid Common Anti-Patterns*

## 🎯 Purpose
Following these guidelines will improve performance while reducing compute and storage expenses.

---

## 📊 Query Design Anti-Patterns

### ❌ **Don't: Use SELECT * Queries**
- **Impact:** Scans unnecessary columns, increases I/O costs by 300-500%
- **When it happens:** Lazy coding, copy-paste from development, lack of column understanding
- **Fix:** Always specify exact columns needed

### ❌ **Don't: Query Large Tables Without Filters**
- **Impact:** Full table scans consume massive compute resources
- **When it happens:** Missing WHERE clauses, testing queries on production data
- **Fix:** Always filter by date ranges, IDs, or status fields first

### ❌ **Don't: Use DISTINCT Unnecessarily** 
- **Impact:** Forces expensive sorting and deduplication operations
- **When it happens:** Unclear data model understanding, defensive programming
- **Fix:** Fix data quality at source, use GROUP BY when aggregating

### ❌ **Don't: Create Cartesian Products (Missing JOIN Conditions)**
- **Impact:** Can generate billions of unnecessary rows, extreme compute costs
- **When it happens:** Missing ON clauses, complex multi-table joins
- **Fix:** Always verify JOIN conditions, use EXPLAIN to check execution plans

### ❌ **Don't: Use ORDER BY Without LIMIT**
- **Impact:** Sorts entire result set even if you only need top records
- **When it happens:** Exploratory queries copied to production, report generation
- **Fix:** Always pair ORDER BY with LIMIT or TOP

### ❌ **Don't: Use Nested Subqueries Excessively**
- **Impact:** Poor query plan optimization, repeated computation
- **When it happens:** Complex reporting requirements, SQL porting from other databases
- **Fix:** Use CTEs (Common Table Expressions) for better readability and optimization

### ❌ **Don't: Use UNION When UNION ALL Suffices**
- **Impact:** Unnecessary deduplication processing
- **When it happens:** Defensive coding, misunderstanding data sources
- **Fix:** Use UNION ALL when duplicates don't matter

---

## 🏗️ Data Pipeline Anti-Patterns

### ❌ **Don't: Create/Drop Tables in DAG Execution**
- **Impact:** Metadata overhead, Time Travel storage costs, performance degradation
- **When it happens:** Temporary processing needs, testing mindset in production
- **Fix:** Use permanent staging tables with TRUNCATE, or temporary tables

### ❌ **Don't: Create Functions/Procedures During DAG Runs**
- **Impact:** Compilation overhead on every execution, metadata bloat
- **When it happens:** Dynamic SQL generation, environment inconsistency
- **Fix:** Deploy functions during release process, use inline SQL logic

### ❌ **Don't: Use Row-by-Row Processing (Cursors)**
- **Impact:** Extremely slow execution, high compute costs per record
- **When it happens:** Procedural programming background, complex business logic
- **Fix:** Use set-based operations, bulk processing with MERGE statements

### ❌ **Don't: Run Multiple Single INSERT Statements**
- **Impact:** Multiple small transactions instead of efficient batch operations
- **When it happens:** Application-style coding, loop-based processing
- **Fix:** Use bulk INSERT, MERGE, or multi-value INSERT statements

### ❌ **Don't: Perform Full Table Refreshes for Incremental Data**
- **Impact:** Processing entire datasets when only small portions change
- **When it happens:** Simple ETL design, lack of change data capture
- **Fix:** Use streams for CDC, implement incremental processing with timestamps

### ❌ **Don't: Run ETL During Peak Business Hours**
- **Impact:** Competing for resources with user queries, higher costs due to scaling
- **When it happens:** Poor scheduling, timezone confusion, urgent fixes
- **Fix:** Schedule heavy processing during off-peak hours, use task scheduling

---

## 🗄️ Storage and Schema Anti-Patterns

### ❌ **Don't: Use VARCHAR Without Size Limits**
- **Impact:** Unnecessary storage overhead, poor query performance
- **When it happens:** Lazy schema design, fear of truncation
- **Fix:** Define appropriate field lengths based on business requirements

### ❌ **Don't: Store Numbers as Strings**
- **Impact:** Larger storage footprint, slower aggregations, incorrect sorting
- **When it happens:** File format issues, generic data loading approaches
- **Fix:** Use proper numeric data types (NUMBER, FLOAT, INTEGER)

### ❌ **Don't: Use Default Time Travel for All Tables**
- **Impact:** Excessive storage costs for temporary or staging data
- **When it happens:** One-size-fits-all approach, lack of data lifecycle understanding
- **Fix:** Set appropriate retention periods (1 day for staging, 7+ for production)

### ❌ **Don't: Ignore Clustering Keys for Large Tables**
- **Impact:** Poor query performance on frequently filtered columns
- **When it happens:** Lack of understanding of query patterns, default table creation
- **Fix:** Implement clustering on commonly filtered columns (dates, IDs, status)

### ❌ **Don't: Create Views That Reference Other Views (View Chaining)**
- **Impact:** Complex execution plans, difficult performance troubleshooting
- **When it happens:** Abstraction layers, reusable component design
- **Fix:** Limit view nesting, use materialized views for complex aggregations

### ❌ **Don't: Store Large Binary Files in Snowflake Tables**
- **Impact:** Extremely expensive storage, poor query performance
- **When it happens:** Document management, image storage, file attachments
- **Fix:** Use external storage (S3, Azure Blob) with references in Snowflake

---

## ⚡ Warehouse and Resource Anti-Patterns

### ❌ **Don't: Use Oversized Warehouses for Small Tasks**
- **Impact:** Paying for unused compute capacity
- **When it happens:** One-size-fits-all warehouse strategy, fear of performance issues
- **Fix:** Match warehouse size to workload requirements, use auto-scaling

### ❌ **Don't: Disable Auto-Suspend on Warehouses**
- **Impact:** Paying for idle compute time
- **When it happens:** Fear of startup delays, misunderstanding of auto-resume
- **Fix:** Enable auto-suspend with appropriate timeouts (1-5 minutes for ETL)

### ❌ **Don't: Run Long-Running Queries on User-Facing Warehouses**
- **Impact:** Poor user experience, resource contention
- **When it happens:** Mixed workload types, insufficient warehouse segregation
- **Fix:** Separate ETL and analytical workloads into different warehouses

### ❌ **Don't: Ignore Query Result Caching**
- **Impact:** Re-executing identical expensive queries
- **When it happens:** Dynamic query generation, parameter variations
- **Fix:** Structure queries to leverage result cache, use query tags for cache management

### ❌ **Don't: Skip Resource Monitors**
- **Impact:** Unexpected cost overruns, no spend control
- **When it happens:** Development environment becomes production-like, runaway queries
- **Fix:** Implement resource monitors with appropriate thresholds and actions

---

## 📁 Data Loading Anti-Patterns

### ❌ **Don't: Load Many Small Files**
- **Impact:** Poor loading performance, metadata overhead
- **When it happens:** Real-time streaming, micro-batch processing
- **Fix:** Aggregate files before loading, use appropriate batch sizes (100MB+ per file)

### ❌ **Don't: Use CSV When Better Formats Available**
- **Impact:** Slower parsing, larger file sizes, data type inference issues
- **When it happens:** Legacy system outputs, default file format choice
- **Fix:** Use Parquet, ORC, or JSON for better compression and performance

### ❌ **Don't: Load Data Without Error Handling**
- **Impact:** Failed loads cause retries, wasted compute on bad data
- **When it happens:** Simple COPY commands, insufficient validation
- **Fix:** Use error handling options, validate data before loading

### ❌ **Don't: Skip File Compression**
- **Impact:** Higher storage costs, slower data transfer
- **When it happens:** Default export settings, lack of compression awareness
- **Fix:** Always compress files (GZIP minimum), use columnar formats when possible

---

## 🔧 Development Environment Anti-Patterns

### ❌ **Don't: Use Production-Sized Data in Development**
- **Impact:** Unnecessary costs for testing and development
- **When it happens:** Complete data copies, realistic testing desires
- **Fix:** Use data sampling, synthetic data, or zero-copy cloning with filters

### ❌ **Don't: Keep Development Warehouses Running 24/7**
- **Impact:** Continuous billing for unused resources
- **When it happens:** Convenience, fear of startup times
- **Fix:** Aggressive auto-suspend settings (1-2 minutes), scheduled shutdown

### ❌ **Don't: Grant Broad Permissions to Developers**
- **Impact:** Accidental expensive operations, security risks
- **When it happens:** Convenience, insufficient role-based access control
- **Fix:** Implement principle of least privilege, create development-specific roles

---

## 🔍 Monitoring and Observability Anti-Patterns

### ❌ **Don't: Skip Query Tagging**
- **Impact:** Inability to track costs by team, project, or application
- **When it happens:** Lack of cost attribution requirements, simple query execution
- **Fix:** Implement consistent query tagging strategy for cost tracking

### ❌ **Don't: Ignore Long-Running Queries**
- **Impact:** Expensive queries consuming disproportionate resources
- **When it happens:** Lack of monitoring, insufficient query optimization
- **Fix:** Set up alerts for queries exceeding time/cost thresholds

### ❌ **Don't: Assume Queries Are Optimized**
- **Impact:** Gradually degrading performance as data volumes grow
- **When it happens:** Set-and-forget approach, lack of performance monitoring
- **Fix:** Regular query performance reviews, automated optimization recommendations

---

## 🎛️ Configuration Anti-Patterns

### ❌ **Don't: Use Default Session Parameters**
- **Impact:** Suboptimal query execution, missed optimization opportunities
- **When it happens:** Lack of parameter understanding, default settings acceptance
- **Fix:** Tune parameters for your workload (QUERY_TAG, USE_CACHED_RESULT, etc.)

### ❌ **Don't: Ignore Transient Tables for Temporary Data**
- **Impact:** Unnecessary Time Travel and Fail-safe costs for temporary data
- **When it happens:** Default table creation, lack of table type understanding
- **Fix:** Use TRANSIENT tables for staging and temporary processing

### ❌ **Don't: Create Separate Tables for Each Day/Month**
- **Impact:** Metadata overhead, poor query performance across time ranges
- **When it happens:** Legacy partitioning mindset, simple data organization
- **Fix:** Use single tables with proper clustering, let Snowflake handle partitioning

---

## 📋 Quick Decision Framework

### **Before Writing Any Query, Ask:**
1. Do I need all these columns? (Avoid SELECT *)
2. Can I filter this data early? (Use WHERE clauses)
3. Is this the right warehouse size for this task?
4. Am I joining tables efficiently?
5. Will this query benefit from caching?

### **Before Creating Any Object, Ask:**
1. Does this need to be permanent or temporary?
2. What's the appropriate Time Travel retention?
3. Should this be clustered on any columns?
4. Can I reuse existing objects instead?
5. Is this the right data type for storage efficiency?

### **Before Loading Data, Ask:**
1. Can I compress this file?
2. Is this the optimal file format?
3. Should I batch multiple files together?
4. Do I have proper error handling?
5. Can I load incrementally instead of full refresh?

---

## 🚀 Implementation Strategy

### **Phase 1: Immediate Actions (Week 1)**
- Audit existing queries for SELECT * usage
- Identify and resize oversized warehouses
- Enable auto-suspend on all warehouses
- Set up basic resource monitors

### **Phase 2: Process Improvements (Weeks 2-4)**
- Review and optimize DAG patterns
- Implement proper staging table strategy
- Set up query performance monitoring
- Create development environment guidelines

### **Phase 3: Systematic Optimization (Weeks 5-8)**
- Implement clustering strategies
- Optimize data loading processes
- Set up cost attribution with query tags
- Create automated optimization alerts

### **Phase 4: Governance and Culture (Ongoing)**
- Regular code reviews focusing on cost optimization
- Developer training on Snowflake best practices
- Monthly cost optimization reviews
- Performance benchmarking and improvement tracking

---

## 📊 Success Metrics

### **Cost Metrics:**
- Monthly credit consumption trend
- Cost per query execution
- Storage cost per TB
- Warehouse utilization rates

### **Performance Metrics:**
- Average query execution time
- Queue wait times
- Data loading speeds
- Pipeline success rates

### **Developer Productivity Metrics:**
- Code review feedback on cost optimization
- Time to deploy new queries/pipelines
- Number of performance-related issues
- Developer satisfaction with tooling and processes

---

## 🔄 Continuous Improvement

### **Weekly Reviews:**
- Top 10 most expensive queries review
- Warehouse utilization analysis
- Failed query pattern identification
- Storage growth trend analysis

### **Monthly Actions:**
- Update warehouse sizing based on usage patterns
- Review and optimize clustering keys
- Assess new Snowflake features for cost benefits
- Update developer guidelines based on lessons learned

### **Quarterly Strategic Reviews:**
- Overall cost optimization ROI assessment
- Benchmark against industry standards
- Technology stack optimization opportunities
- Training and skill development needs

---

*This guideline should be reviewed and updated quarterly as Snowflake introduces new features and as your data platform evolves.*
