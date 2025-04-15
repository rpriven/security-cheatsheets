# GitHub Repository Cheatsheet

## Quick Reference Guide for Git and GitHub Workflows

| Command | Description | Example | Notes |
|---------|-------------|---------|-------|
| **Repository Setup** ||||
| `git init` | Initialize a new local repository | `git init my-project` | Creates a new .git directory |
| `git clone [url]` | Clone a repository from remote | `git clone https://github.com/user/repo.git` | Downloads full history |
| `git remote add origin [url]` | Connect local repo to remote | `git remote add origin https://github.com/user/repo.git` | Sets up "origin" remote |
| `git remote -v` | List remote connections | `git remote -v` | Shows fetch/push URLs |
| **Basic Workflow** ||||
| `git status` | Check repository status | `git status` | Shows modified/staged files |
| `git add [file]` | Stage changes | `git add index.html` or `git add .` | Prepares files for commit |
| `git commit -m "[message]"` | Commit staged changes | `git commit -m "Fix navigation bug"` | Creates a commit snapshot |
| `git pull` | Fetch and merge remote changes | `git pull origin main` | Updates local branch |
| `git push` | Push commits to remote | `git push origin main` | Uploads local commits |
| **Branching** ||||
| `git branch` | List local branches | `git branch` | Current branch has asterisk |
| `git branch [name]` | Create new branch | `git branch feature-login` | Creates branch at current commit |
| `git checkout [branch]` | Switch branches | `git checkout feature-login` | Updates working directory |
| `git checkout -b [name]` | Create and checkout branch | `git checkout -b feature-login` | Combines branch + checkout |
| `git merge [branch]` | Merge branch into current | `git merge feature-login` | Integrates branch changes |
| `git branch -d [name]` | Delete branch | `git branch -d feature-login` | Removes merged branch |
| `git branch -D [name]` | Force delete branch | `git branch -D feature-login` | Removes unmerged branch |
| **Branching Strategies** ||||
| Git Flow | Main/Develop with feature branches | `git checkout -b feature/login develop` | Complex but structured |
| GitHub Flow | Single main with feature branches | `git checkout -b feature-login main` | Simpler, PR-based |
| Trunk-Based | Short-lived branches off main | `git checkout -b fix-404-error main` | Quick integration cycles |
| **Pull Request Workflow** ||||
| Create PR | Via GitHub UI | Click "New pull request" on repo page | Compare branches |
| Review PR | Via GitHub UI | Add comments, request changes | Code review process |
| Merge PR | Via GitHub UI | Click "Merge pull request" | Can squash or rebase |
| `git fetch origin pull/ID/head:BRANCHNAME` | Get PR locally | `git fetch origin pull/123/head:pr-123` | For local PR testing |
| **History & Changes** ||||
| `git log` | View commit history | `git log --oneline` | Shows commit list |
| `git diff` | Show unstaged changes | `git diff` | Compare working to staged |
| `git diff --staged` | Show staged changes | `git diff --staged` | Compare staged to last commit |
| `git reset HEAD [file]` | Unstage changes | `git reset HEAD index.html` | Keeps file changes |
| `git checkout -- [file]` | Discard changes | `git checkout -- index.html` | Loses uncommitted changes |
| **Advanced Commands** ||||
| `git stash` | Stash uncommitted changes | `git stash save "WIP homepage"` | Temporarily stores changes |
| `git stash pop` | Apply stashed changes | `git stash pop` | Reapplies and drops stash |
| `git rebase [branch]` | Reapply commits on branch | `git rebase main` | Rewrites commit history |
| `git tag [name]` | Create a tag | `git tag v1.0.0` | Marks specific commit |
| `git cherry-pick [commit]` | Apply commit to current branch | `git cherry-pick abc123` | Takes single commit |

## Common Branching Strategies

1. **Git Flow**
   - `main` - production-ready code
   - `develop` - integration branch for features
   - `feature/*` - new features
   - `release/*` - prepare for release
   - `hotfix/*` - urgent production fixes

2. **GitHub Flow**
   - `main` - always deployable
   - feature branches - all work happens here
   - pull requests - for code review and discussion
   - deploy after merge to main

3. **Trunk-Based Development**
   - `main` - primary branch
   - short-lived feature branches
   - frequent integration to main
   - feature flags for incomplete work
