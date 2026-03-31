README Documentation Guide
Your README should explain:

1. Overview
What does your aggregator do? Why three different feeds?

2. Feed Schemas
Show the different field names for each vendor. Make a table showing the mapping.

3. Normalization Strategy
How do you handle three different schemas? .get() approach? Field mapping?

4. Deduplication Logic
Explain:

How you identify duplicates (type, value) tuple
How you decide which to keep (highest confidence)
How you merge sources lists
5. Test Data
Document what's in your test feeds:

Total indicators per feed
Which indicators are duplicates across feeds
Expected dedup count
6. Output Formats
Describe the three outputs and what each is used for.