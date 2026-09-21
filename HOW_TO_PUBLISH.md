# How to make these genuinely yours and publish on GitHub

You have 3 working projects: `port_scanner/`, `log_analyzer/`, `phishing_detector/`.
Follow these steps for **each one** (as 3 separate GitHub repos, or one repo with
3 folders — either is fine).

## Step 1 — Actually run it and read the code
Don't skip this. Open each `.py` file, read it top to bottom, and run it
yourself so you can see the real output. This is what lets you answer
interview questions confidently.

```bash
python port_scanner.py 127.0.0.1 --start 1 --end 1024
python log_analyzer.py sample_auth.log
python phishing_detector.py "https://example.com"
```

## Step 2 — Tweak something (makes it genuinely yours)
Small changes are enough — e.g.:
- Add 2-3 more ports to `COMMON_PORTS` in the scanner.
- Add a new suspicious keyword to the phishing detector.
- Change the `BRUTE_FORCE_THRESHOLD` in the log analyzer and explain why.
Write a one-line comment explaining your change. This is normal — every
developer builds on examples and documentation, the key is you understand
and can explain every part.

## Step 3 — Create a GitHub repo
```bash
cd port_scanner
git init
git add .
git commit -m "Add simple multithreaded TCP port scanner"
git branch -M main
git remote add origin https://github.com/RajJoshi1510/port-scanner.git
git push -u origin main
```
(Create the empty repo first on github.com, then copy its URL for the
`remote add` command above.) Repeat for the other two folders.

## Step 4 — Prepare 2-3 talking points per project
For each project, be ready to answer:
1. What problem does it solve?
2. Walk me through the code / logic.
3. What would you improve or add next?
(The "Possible extensions" section in each README gives you ready answers
for #3.)
