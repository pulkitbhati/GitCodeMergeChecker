import streamlit as st
import subprocess
import os
import tempfile
from pathlib import Path
import pandas as pd
from datetime import datetime
import json
import requests
from urllib.parse import urlparse
import base64

class GitHubBranchMergeChecker:
    def __init__(self):
        self.github_token = None
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Git-Branch-Merge-Checker'
        }
        self.projects_config = None
    
    def load_projects_config(self, config_path="projects_config.json"):
        """Load projects configuration from JSON file"""
        try:
            import json
            with open(config_path, 'r') as f:
                self.projects_config = json.load(f)
            return True, self.projects_config
        except FileNotFoundError:
            return False, "Configuration file not found. Please create projects_config.json"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in configuration file: {str(e)}"
        except Exception as e:
            return False, f"Error loading configuration: {str(e)}"
    
    def get_projects_list(self):
        """Get list of configured projects"""
        if not self.projects_config:
            return []
        return self.projects_config.get('projects', [])
    
    def fetch_organization_repos(self, org_name):
        """Fetch all repositories from a GitHub organization"""
        repos = []
        page = 1
        per_page = 100
        
        try:
            while True:
                url = f"https://api.github.com/orgs/{org_name}/repos"
                params = {
                    'page': page,
                    'per_page': per_page,
                    'sort': 'updated',
                    'type': 'all'  # all, public, private, forks, sources, member
                }
                
                response = requests.get(url, headers=self.headers, params=params, timeout=15)
                
                if response.status_code == 200:
                    page_repos = response.json()
                    
                    if not page_repos:  # No more repos
                        break
                    
                    for repo in page_repos:
                        repos.append({
                            'name': repo['name'],
                            'full_name': repo['full_name'],
                            'description': repo.get('description', 'No description'),
                            'private': repo['private'],
                            'default_branch': repo['default_branch'],
                            'updated_at': repo['updated_at'],
                            'language': repo.get('language', 'Unknown'),
                            'size': repo['size'],
                            'stars': repo['stargazers_count'],
                            'forks': repo['forks_count']
                        })
                    
                    # If we got less than per_page, we're on the last page
                    if len(page_repos) < per_page:
                        break
                        
                    page += 1
                    
                    # Safety check
                    if page > 20:  # Max 2000 repos
                        st.warning("⚠️ Too many repositories! Showing first 2000.")
                        break
                        
                elif response.status_code == 404:
                    return [], f"Organization '{org_name}' not found or not accessible"
                elif response.status_code == 403:
                    return [], "Access forbidden. You may need a GitHub token with organization access."
                else:
                    return [], f"Error fetching repositories: HTTP {response.status_code}"
                    
        except requests.exceptions.RequestException as e:
            return [], f"Connection error: {str(e)}"
        
        return repos, None
    
    def convert_repos_to_projects(self, repos, org_name, default_source_branch="develop", default_dest_branch="main"):
        """Convert GitHub repos to project configuration format"""
        projects = []
        
        for repo in repos:
            # Skip forks by default (can be made configurable)
            repo_name = repo['name']
            
            projects.append({
                'name': repo_name,
                'owner': org_name,
                'repo': repo_name,
                'description': repo['description'] or f"{repo_name} repository",
                'default_source_branch': default_source_branch,
                'default_dest_branch': repo['default_branch'] or default_dest_branch,
                'private': repo['private'],
                'language': repo['language'],
                'last_updated': repo['updated_at'],
                'stars': repo['stars'],
                'size_kb': repo['size']
            })
        
        return projects
        
    def set_github_token(self, token):
        """Set GitHub personal access token for API calls"""
        self.github_token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Git-Branch-Merge-Checker'
        }
    
    def check_rate_limit(self):
        """Check GitHub API rate limit status"""
        try:
            url = "https://api.github.com/rate_limit"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                rate_info = response.json()
                return True, rate_info
            else:
                return False, None
                
        except requests.exceptions.RequestException:
            return False, None
    
    def parse_github_url(self, url):
        """Parse GitHub URL to extract owner and repo name"""
        try:
            # Handle different GitHub URL formats
            if 'github.com' not in url:
                return None, None
                
            # Remove .git if present
            url = url.replace('.git', '')
            
            # Extract from different formats
            if url.startswith('https://github.com/'):
                parts = url.replace('https://github.com/', '').split('/')
            elif url.startswith('git@github.com:'):
                parts = url.replace('git@github.com:', '').split('/')
            else:
                # Try to extract from any github.com URL
                parsed = urlparse(url)
                if 'github.com' in parsed.netloc:
                    parts = parsed.path.strip('/').split('/')
                else:
                    return None, None
            
            if len(parts) >= 2:
                return parts[0], parts[1]
            return None, None
        except Exception:
            return None, None
    
    def test_github_connection(self, owner, repo):
        """Test if we can access the GitHub repository"""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                repo_info = response.json()
                return True, repo_info
            elif response.status_code == 404:
                return False, "Repository not found or not accessible. This could mean:\n• The repository is private and you need a GitHub token\n• The repository doesn't exist\n• The owner/repo name is incorrect"
            elif response.status_code == 403:
                if 'rate limit' in response.text.lower():
                    return False, "Rate limit exceeded. Please add a GitHub token to increase rate limits."
                else:
                    return False, "Access forbidden. This could mean:\n• You need a GitHub token for private repositories\n• Your token doesn't have the required permissions\n• The repository has restricted access"
            elif response.status_code == 401:
                return False, "Authentication failed. Please check your GitHub token."
            else:
                try:
                    error_detail = response.json().get('message', response.text)
                except:
                    error_detail = response.text
                return False, f"HTTP {response.status_code}: {error_detail}"
                
        except requests.exceptions.RequestException as e:
            return False, f"Connection error: {str(e)}"
    
    def validate_projects_bulk(self, projects):
        """Validate multiple projects and return their status"""
        validation_results = []
        
        for project in projects:
            success, result = self.test_github_connection(project['owner'], project['repo'])
            validation_results.append({
                'project': project,
                'accessible': success,
                'message': result if not success else 'Repository accessible',
                'repo_info': result if success else None
            })
        
        return validation_results
    
    def get_github_branches(self, owner, repo):
        """Get list of ALL branches from GitHub repository with pagination"""
        branches = []
        page = 1
        per_page = 100  # Maximum allowed by GitHub API
        
        try:
            while True:
                url = f"https://api.github.com/repos/{owner}/{repo}/branches"
                params = {
                    'page': page,
                    'per_page': per_page
                }
                
                response = requests.get(url, headers=self.headers, params=params, timeout=15)
                
                if response.status_code == 200:
                    page_branches = response.json()
                    
                    if not page_branches:  # No more branches
                        break
                        
                    branches.extend([branch['name'] for branch in page_branches])
                    
                    # If we got less than per_page, we're on the last page
                    if len(page_branches) < per_page:
                        break
                        
                    page += 1
                    
                    # Safety check to prevent infinite loops
                    if page > 50:  # Max 5000 branches
                        st.warning("⚠️ Too many branches! Showing first 5000 branches.")
                        break
                        
                else:
                    st.error(f"Failed to fetch branches: HTTP {response.status_code}")
                    if page == 1:  # If first page fails, return empty
                        return []
                    else:  # If later page fails, return what we have so far
                        break
                        
        except requests.exceptions.RequestException as e:
            st.error(f"Error fetching branches: {str(e)}")
            return branches  # Return what we got so far
        
        # Sort branches for better UX
        branches.sort()
        
        # Show count
        if len(branches) > 0:
            st.success(f"📊 Found {len(branches)} branches")
        
        return branches
    
    def get_branch_commit(self, owner, repo, branch):
        """Get the latest commit SHA for a branch"""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                branch_info = response.json()
                return branch_info['commit']['sha']
            return None
            
        except requests.exceptions.RequestException:
            return None
    
    def compare_branches_github(self, owner, repo, source_branch, dest_branch, show_errors=True):
        """Compare two branches using GitHub API"""
        try:
            # Use GitHub's compare API
            url = f"https://api.github.com/repos/{owner}/{repo}/compare/{dest_branch}...{source_branch}"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                comparison = response.json()
                return comparison, None
            else:
                error_msg = f"HTTP {response.status_code}"
                if response.status_code == 404:
                    error_msg += f" - Repository or branch not found ({owner}/{repo})\n"
                    error_msg += f"   Checking: '{source_branch}' → '{dest_branch}'\n"
                    error_msg += f"   API URL: .../{dest_branch}...{source_branch}\n"
                    error_msg += f"   This means either:\n"
                    error_msg += f"   • Repository '{owner}/{repo}' doesn't exist or is private\n"
                    error_msg += f"   • Branch '{source_branch}' doesn't exist\n"
                    error_msg += f"   • Branch '{dest_branch}' doesn't exist"
                elif response.status_code == 403:
                    error_msg += " - Access forbidden (check token permissions)"
                elif response.status_code == 401:
                    error_msg += " - Authentication required"
                
                if show_errors:
                    st.error(f"Failed to compare branches: {error_msg}")
                return None, error_msg
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Network error: {str(e)}"
            if show_errors:
                st.error(f"Error comparing branches: {error_msg}")
            return None, error_msg
    
    def get_commits_between_branches(self, owner, repo, source_branch, dest_branch, show_errors=True):
        """Get commits that are in source branch but not in destination branch"""
        try:
            # First try to get comparison - don't show errors for bulk operations
            comparison, error = self.compare_branches_github(owner, repo, source_branch, dest_branch, show_errors)
            
            if comparison and 'commits' in comparison:
                commits = []
                for commit in comparison['commits']:
                    commits.append({
                        'Hash': commit['sha'][:8],
                        'Author': commit['commit']['author']['name'],
                        'Date': commit['commit']['author']['date'],
                        'Message': commit['commit']['message'].split('\n')[0]  # First line only
                    })
                return commits, comparison, None
            elif error:
                return [], None, error
            
            return [], None, None
            
        except Exception as e:
            error_msg = f"Error getting commits: {str(e)}"
            if show_errors:
                st.error(error_msg)
            return [], None, error_msg
    
    def bulk_check_projects(self, source_branch, dest_branch, selected_projects=None, projects_list=None, progress_callback=None):
        """Check merge status across multiple projects"""
        # Use provided projects list or fall back to config
        if projects_list is not None:
            projects = projects_list
        elif self.projects_config:
            projects = self.get_projects_list()
        else:
            return []
        
        if selected_projects:
            projects = [p for p in projects if p['name'] in selected_projects]
        
        results = []
        
        for i, project in enumerate(projects):
            # Call progress callback if provided
            if progress_callback:
                progress_callback(i, len(projects), project['name'])
            try:
                # Use project-specific branches or provided ones
                src_branch = source_branch or project.get('default_source_branch', 'develop')
                dst_branch = dest_branch or project.get('default_dest_branch', 'main')
                
                # Get commits between branches (don't show errors immediately for bulk operations)
                commits, comparison, error = self.get_commits_between_branches(
                    project['owner'], 
                    project['repo'], 
                    src_branch, 
                    dst_branch,
                    show_errors=False  # Don't show errors immediately in bulk mode
                )
                
                if error:
                    # Handle API errors gracefully
                    results.append({
                        'project': project,
                        'source_branch': src_branch,
                        'dest_branch': dst_branch,
                        'commits': [],
                        'comparison': None,
                        'is_merged': False,
                        'commits_ahead': 0,
                        'commits_behind': 0,
                        'status': 'error',
                        'error': error
                    })
                else:
                    # Compile successful result
                    result = {
                        'project': project,
                        'source_branch': src_branch,
                        'dest_branch': dst_branch,
                        'commits': commits,
                        'comparison': comparison,
                        'is_merged': len(commits) == 0,
                        'commits_ahead': len(commits),
                        'commits_behind': comparison.get('behind_by', 0) if comparison else 0,
                        'status': 'success'
                    }
                    results.append(result)
                
            except Exception as e:
                # Handle unexpected errors for individual projects
                results.append({
                    'project': project,
                    'source_branch': src_branch if 'src_branch' in locals() else 'unknown',
                    'dest_branch': dst_branch if 'dst_branch' in locals() else 'unknown',
                    'commits': [],
                    'comparison': None,
                    'is_merged': False,
                    'commits_ahead': 0,
                    'commits_behind': 0,
                    'status': 'error',
                    'error': f"Unexpected error: {str(e)}"
                })
        
        return results

    def bulk_check_projects_with_config(self, project_configs, progress_callback=None):
        """Check merge status across multiple projects with individual branch configurations"""
        results = []
        
        for i, config in enumerate(project_configs):
            # Call progress callback if provided
            if progress_callback:
                progress_callback(i, len(project_configs), config['project']['name'])
            
            project = config['project']
            src_branch = config['source_branch']
            dst_branch = config['dest_branch']
            
            try:
                # Get commits between branches (don't show errors immediately for bulk operations)
                commits, comparison, error = self.get_commits_between_branches(
                    project['owner'], 
                    project['repo'], 
                    src_branch, 
                    dst_branch,
                    show_errors=False  # Don't show errors immediately in bulk mode
                )
                
                if error:
                    # Handle API errors gracefully
                    results.append({
                        'project': project,
                        'source_branch': src_branch,
                        'dest_branch': dst_branch,
                        'commits': [],
                        'comparison': None,
                        'is_merged': False,
                        'commits_ahead': 0,
                        'commits_behind': 0,
                        'status': 'error',
                        'error': error
                    })
                else:
                    # Compile successful result
                    result = {
                        'project': project,
                        'source_branch': src_branch,
                        'dest_branch': dst_branch,
                        'commits': commits,
                        'comparison': comparison,
                        'is_merged': len(commits) == 0,
                        'commits_ahead': len(commits),
                        'commits_behind': comparison.get('behind_by', 0) if comparison else 0,
                        'status': 'success'
                    }
                    results.append(result)
                
            except Exception as e:
                # Handle unexpected errors for individual projects
                results.append({
                    'project': project,
                    'source_branch': src_branch,
                    'dest_branch': dst_branch,
                    'commits': [],
                    'comparison': None,
                    'is_merged': False,
                    'commits_ahead': 0,
                    'commits_behind': 0,
                    'status': 'error',
                    'error': f"Unexpected error: {str(e)}"
                })
        
        return results

class GitBranchMergeChecker:
    def __init__(self, repo_path=None):
        self.repo_path = repo_path
        
    def is_git_repository(self, path):
        """Check if the given path is a Git repository"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=path,
                capture_output=True,
                text=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def get_branches(self, repo_path):
        """Get list of all branches in the repository"""
        try:
            # Get local branches
            result = subprocess.run(
                ['git', 'branch', '-a'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            branches = []
            for line in result.stdout.strip().split('\n'):
                branch = line.strip()
                if branch:
                    # Remove asterisk and whitespace
                    branch = branch.replace('*', '').strip()
                    # Remove remotes/ prefix for remote branches
                    if branch.startswith('remotes/'):
                        branch = branch.replace('remotes/', '')
                    branches.append(branch)
            
            # Remove duplicates and sort
            return sorted(list(set(branches)))
            
        except subprocess.CalledProcessError as e:
            st.error(f"Error getting branches: {e}")
            return []
    
    def fetch_latest_changes(self, repo_path):
        """Fetch latest changes from remote"""
        try:
            result = subprocess.run(
                ['git', 'fetch', '--all'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            st.warning(f"Could not fetch latest changes: {e}")
            return False
    
    def get_merge_base(self, repo_path, source_branch, dest_branch):
        """Get the merge base between two branches"""
        try:
            result = subprocess.run(
                ['git', 'merge-base', source_branch, dest_branch],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None
    
    def get_commits_not_in_branch(self, repo_path, source_branch, dest_branch):
        """Get commits that are in source branch but not in destination branch"""
        try:
            # Get commits in source but not in destination
            result = subprocess.run(
                ['git', 'log', '--oneline', f'{dest_branch}..{source_branch}'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = []
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split(' ', 1)
                        commit_hash = parts[0]
                        commit_message = parts[1] if len(parts) > 1 else ''
                        commits.append({
                            'hash': commit_hash,
                            'message': commit_message
                        })
            
            return commits
            
        except subprocess.CalledProcessError as e:
            st.error(f"Error getting commits: {e}")
            return []
    
    def get_detailed_commit_info(self, repo_path, source_branch, dest_branch):
        """Get detailed information about commits"""
        try:
            result = subprocess.run(
                ['git', 'log', '--pretty=format:%H|%an|%ad|%s', '--date=iso', f'{dest_branch}..{source_branch}'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = []
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split('|')
                        if len(parts) >= 4:
                            commits.append({
                                'Hash': parts[0][:8],  # Short hash
                                'Author': parts[1],
                                'Date': parts[2],
                                'Message': parts[3]
                            })
            
            return commits
            
        except subprocess.CalledProcessError as e:
            st.error(f"Error getting detailed commit info: {e}")
            return []
    
    def check_branch_exists(self, repo_path, branch_name):
        """Check if a branch exists"""
        try:
            subprocess.run(
                ['git', 'rev-parse', '--verify', branch_name],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    def get_branch_commit_count(self, repo_path, branch_name):
        """Get the number of commits in a branch"""
        try:
            result = subprocess.run(
                ['git', 'rev-list', '--count', branch_name],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return int(result.stdout.strip())
        except subprocess.CalledProcessError:
            return 0

def main():
    st.set_page_config(
        page_title="Git Branch Merge Checker",
        page_icon="🔀",
        layout="wide"
    )
    
    st.title("🔀 Git Branch Merge Checker")
    st.markdown("Check if code from source branch is completely merged into destination branch")
    
    # Initialize session state
    if 'local_checker' not in st.session_state:
        st.session_state.local_checker = GitBranchMergeChecker()
    if 'github_checker' not in st.session_state:
        st.session_state.github_checker = GitHubBranchMergeChecker()
    
    # Mode selection with tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🐙 GitHub Repository (Remote)", "📁 Local Repository", "🏢 Bulk Project Check", "📖 Help & Documentation"])
    
    # Bulk Project Check Mode
    with tab3:
        # Bulk project checking mode
        st.header("🏢 Bulk Project Merge Status Check")
        
        # GitHub token configuration (moved up for organization discovery)
        with st.expander("🔐 GitHub Token Configuration", expanded=True):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                github_token = st.text_input(
                    "GitHub Personal Access Token",
                    type="password",
                    help="Required for private organizational repositories and auto-discovery"
                )
                
                if github_token:
                    st.session_state.github_checker.set_github_token(github_token)
                    st.success("✅ Token configured")
                else:
                    st.info("💡 Without a token, you have limited API calls (60/hour) and can't access private repos")
            
            with col2:
                st.markdown("**Need a token?**")
                st.markdown("[Generate here](https://github.com/settings/tokens)")
                
                # Test token
                if st.button("🧪 Test Token"):
                    success, rate_info = st.session_state.github_checker.check_rate_limit()
                    if success and rate_info:
                        core_limit = rate_info['rate']
                        st.success(f"✅ Token valid! Rate limit: {core_limit['remaining']}/{core_limit['limit']}")
                    else:
                        st.error("❌ Token test failed")
        
        # Project source selection
        project_source = st.radio(
            "Choose project source:",
            ["📄 Load from Config File", "🏢 Auto-discover from Organization"],
            horizontal=True
        )
        
        if project_source == "🏢 Auto-discover from Organization":
            # Organization auto-discovery
            st.header("🏢 Organization Repository Discovery")
            
            org_url = st.text_input(
                "Organization URL or Name",
                value="https://github.com/PriorityTechnologyHoldings",
                placeholder="https://github.com/YourOrganization or just 'YourOrganization'",
                help="Enter GitHub organization URL or just the organization name"
            )
            
            # Keyword filter input
            keyword_filter = st.text_input(
                "🔍 Repository Name Filter (Optional)",
                placeholder="Enter keyword to filter repositories (e.g., 'api', 'frontend', 'service')",
                help="Only repositories containing this keyword will be discovered. Leave empty to fetch all repositories. Minimum 3 characters required."
            )
            
            # Validate keyword length if provided
            keyword_valid = True
            if keyword_filter and len(keyword_filter.strip()) < 3:
                st.warning("⚠️ Keyword must be at least 3 characters long")
                keyword_valid = False
            elif keyword_filter:
                st.info(f"🎯 Will search for repositories containing: **{keyword_filter.strip()}**")
            
            if org_url:
                # Extract org name from URL or use as-is
                if "github.com/" in org_url:
                    org_name = org_url.split("github.com/")[-1].strip("/")
                else:
                    org_name = org_url.strip("/")
                
                st.info(f"🎯 Organization: **{org_name}**")
                
                if st.button("🔍 Discover Repositories", type="secondary"):
                    if not github_token:
                        st.error("❌ GitHub token required for organization repository discovery!")
                    elif keyword_filter and len(keyword_filter.strip()) < 3:
                        st.error("❌ Keyword must be at least 3 characters long!")
                    else:
                        search_text = f" matching '{keyword_filter.strip()}'" if keyword_filter and keyword_filter.strip() else ""
                        with st.spinner(f"🔍 Fetching repositories from {org_name}{search_text}..."):
                            repos, error = st.session_state.github_checker.fetch_organization_repos(org_name)
                            
                            if error:
                                st.error(f"❌ {error}")
                            else:
                                # Apply keyword filter first (case-insensitive)
                                if keyword_filter and keyword_filter.strip():
                                    keyword_lower = keyword_filter.strip().lower()
                                    original_count = len(repos)
                                    repos = [r for r in repos if keyword_lower in r['name'].lower()]
                                    st.success(f"✅ Found {len(repos)} repositories matching '{keyword_filter.strip()}' (filtered from {original_count} total)")
                                else:
                                    st.success(f"✅ Found {len(repos)} repositories!")
                                
                                # Additional filter options
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    min_stars = st.number_input("Min stars", min_value=0, value=0)
                                    languages = list(set([r['language'] for r in repos if r['language']]))
                                    selected_languages = st.multiselect("Filter by language", languages)
                                
                                with col2:
                                    sort_by = st.selectbox("Sort by", ["updated", "name", "stars", "size"])
                                
                                # Apply additional filters
                                filtered_repos = repos
                                if selected_languages:
                                    filtered_repos = [r for r in filtered_repos if r['language'] in selected_languages]
                                if min_stars > 0:
                                    filtered_repos = [r for r in filtered_repos if r['stars'] >= min_stars]
                                
                                # Sort repos
                                if sort_by == "updated":
                                    filtered_repos.sort(key=lambda x: x['updated_at'], reverse=True)
                                elif sort_by == "name":
                                    filtered_repos.sort(key=lambda x: x['name'])
                                elif sort_by == "stars":
                                    filtered_repos.sort(key=lambda x: x['stars'], reverse=True)
                                elif sort_by == "size":
                                    filtered_repos.sort(key=lambda x: x['size'], reverse=True)
                                
                                # Show repositories
                                st.subheader(f"📋 {len(filtered_repos)} Repositories Found")
                                
                                # Repository selection
                                repo_data = []
                                for repo in filtered_repos:
                                    description = repo['description'] or 'No description'
                                    truncated_desc = description[:50] + '...' if len(description) > 50 else description
                                    
                                    repo_data.append({
                                        'Select': True,
                                        'Repository': repo['name'],
                                        'Description': truncated_desc,
                                        'Language': repo['language'] or 'N/A',
                                        'Stars': repo['stars'],
                                        'Private': '🔒' if repo['private'] else '🌍',
                                        'Updated': repo['updated_at'][:10]  # Just date part
                                    })
                                
                                if repo_data:
                                    # Convert repos to project format
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        default_source = st.text_input("Default source branch", value="develop")
                                    with col2:
                                        default_dest = st.text_input("Default destination branch", value="main")
                                    
                                    projects = st.session_state.github_checker.convert_repos_to_projects(
                                        filtered_repos, org_name, default_source, default_dest
                                    )
                                    
                                    # Store discovered projects
                                    st.session_state.discovered_projects = projects
                                    st.session_state.project_source = "discovered"
                                    
                                    # Show summary
                                    st.success(f"🎉 Ready to check {len(projects)} repositories!")
        
        else:
            # Load projects configuration
            config_loaded, config_result = st.session_state.github_checker.load_projects_config()
            
            if not config_loaded:
                st.error(f"❌ {config_result}")
                st.markdown("""
                ### 📋 Setup Instructions:
                
                1. **Create `projects_config.json`** in your project directory
                2. **Configure your projects** with this format:
                
                ```json
                {
                  "projects": [
                    {
                      "name": "Project Name",
                      "owner": "organization-name",
                      "repo": "repository-name", 
                      "description": "Project description",
                      "default_source_branch": "develop",
                      "default_dest_branch": "main"
                    }
                  ]
                }
                ```
                
                3. **Add your GitHub token** above for private repositories
                4. **Select projects** and branches to check
                """)
                return
            else:
                st.session_state.config_projects = st.session_state.github_checker.get_projects_list()
                st.session_state.project_source = "config"
        
        # Determine which projects to use
        if st.session_state.get('project_source') == "discovered":
            projects = st.session_state.get('discovered_projects', [])
        elif st.session_state.get('project_source') == "config":
            projects = st.session_state.get('config_projects', [])
        else:
            projects = []
        
        # Continue with project selection and bulk checking
        if not projects:
            if st.session_state.get('project_source') == "discovered":
                st.info("👆 Click 'Discover Repositories' to find projects from your organization")
            else:
                st.warning("⚠️ No projects found. Try auto-discovery or check your config file.")
        else:

                
                # Projects selection
                st.header("📋 Select Projects to Check")
                
                # Display available projects
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.subheader("Available Projects")
                    
                    # Show projects in a nice format
                    project_options = []
                    for project in projects:
                        display_name = f"{project['name']} ({project['owner']}/{project['repo']})"
                        project_options.append(display_name)
                    
                    selected_project_displays = st.multiselect(
                        "Select projects to check:",
                        options=project_options,
                        default=project_options,  # Select all by default
                        help="Choose which projects to include in the bulk check"
                    )
                    
                    # Map back to project names
                    selected_project_names = []
                    for display in selected_project_displays:
                        for project in projects:
                            expected_display = f"{project['name']} ({project['owner']}/{project['repo']})"
                            if display == expected_display:
                                selected_project_names.append(project['name'])
                                break
                
                with col2:
                    st.subheader("Branch Configuration")
                    
                    # Global branch override options
                    use_global_branches = st.checkbox(
                        "Use same branches for all projects",
                        help="Override individual project branch settings"
                    )
                    
                    if use_global_branches:
                        st.info("🌐 **Global Mode:** All projects will use the same source and destination branches")
                        
                        global_source = st.text_input(
                            "Global Source Branch",
                            placeholder="e.g., develop, staging, feature/branch-name",
                            help="This branch will be used as source for ALL selected projects"
                        )
                        global_dest = st.text_input(
                            "Global Destination Branch", 
                            placeholder="e.g., main, master, production",
                            help="This branch will be used as destination for ALL selected projects"
                        )
                        
                        if global_source and global_dest:
                            st.success(f"✅ Will check: `{global_source}` → `{global_dest}` for all projects")
                        elif global_source or global_dest:
                            st.warning("⚠️ Please specify both source and destination branches")
                    else:
                        global_source = None
                        global_dest = None
                        st.info("⚙️ **Individual Mode:** Each project can have different branches (configure below)")
                
                # Project configuration
                if selected_project_names:
                    st.subheader("📊 Project Configuration")
                    
                    # Initialize configured projects
                    configured_projects = []
                    
                    for project in projects:
                        if project['name'] in selected_project_names:
                            # Apply global override or use project defaults
                            if use_global_branches and global_source and global_dest:
                                src_branch = global_source
                                dst_branch = global_dest
                            else:
                                src_branch = project.get('default_source_branch', 'develop')
                                dst_branch = project.get('default_dest_branch', 'main')
                            
                            configured_projects.append({
                                'project': project,
                                'source_branch': src_branch,
                                'dest_branch': dst_branch
                            })
                    
                    # Editable Configuration Table
                    if configured_projects:
                        st.subheader("📋 Configuration & Branch Selection")
                        
                        if use_global_branches:
                            if global_source and global_dest:
                                st.success(f"✅ Using global branches: `{global_source}` → `{global_dest}` for all projects")
                            else:
                                st.warning("⚠️ Please specify both global source and destination branches above.")
                        else:
                            st.info("💡 Configure individual branches for each project in the table below")
                        
                        # Initialize session state for individual project configs
                        if 'individual_configs' not in st.session_state:
                            st.session_state.individual_configs = {}
                        
                        # Create configuration table with inline editing
                        updated_configured_projects = []
                        
                        for i, config in enumerate(configured_projects):
                            project = config['project']
                            project_key = f"{project['owner']}/{project['repo']}"
                            
                            # Initialize individual config if not exists
                            if project_key not in st.session_state.individual_configs:
                                st.session_state.individual_configs[project_key] = {
                                    'source_branch': config['source_branch'],
                                    'dest_branch': config['dest_branch']
                                }
                            
                            with st.container():
                                st.markdown(f"**{i+1}. {project['name']}** - `{project_key}`")
                                
                                col1, col2, col3, col4 = st.columns([3, 2, 2, 1])
                                
                                with col1:
                                    st.markdown(f"*{project.get('description', 'No description')[:60]}...*")
                                
                                with col2:
                                    if use_global_branches and global_source:
                                        st.text_input(
                                            "Source Branch:",
                                            value=global_source,
                                            key=f"src_readonly_{project_key}",
                                            disabled=True,
                                            help="Using global source branch"
                                        )
                                        final_source = global_source
                                    else:
                                        final_source = st.text_input(
                                            "Source Branch:",
                                            value=st.session_state.individual_configs[project_key]['source_branch'],
                                            key=f"src_edit_{project_key}",
                                            placeholder="e.g., develop, staging"
                                        )
                                        st.session_state.individual_configs[project_key]['source_branch'] = final_source
                                
                                with col3:
                                    if use_global_branches and global_dest:
                                        st.text_input(
                                            "Destination Branch:",
                                            value=global_dest,
                                            key=f"dst_readonly_{project_key}",
                                            disabled=True,
                                            help="Using global destination branch"
                                        )
                                        final_dest = global_dest
                                    else:
                                        final_dest = st.text_input(
                                            "Destination Branch:",
                                            value=st.session_state.individual_configs[project_key]['dest_branch'],
                                            key=f"dst_edit_{project_key}",
                                            placeholder="e.g., main, master"
                                        )
                                        st.session_state.individual_configs[project_key]['dest_branch'] = final_dest
                                
                                with col4:
                                    if not use_global_branches:
                                        if st.button("🔄", key=f"reset_individual_{project_key}", help="Reset to defaults"):
                                            st.session_state.individual_configs[project_key]['source_branch'] = project.get('default_source_branch', 'develop')
                                            st.session_state.individual_configs[project_key]['dest_branch'] = project.get('default_dest_branch', 'main')
                                            st.rerun()
                                
                                # Update the configured project with final values
                                updated_configured_projects.append({
                                    'project': project,
                                    'source_branch': final_source,
                                    'dest_branch': final_dest
                                })
                                
                                st.markdown("---")
                        
                        # Update configured_projects with the edited values
                        configured_projects = updated_configured_projects
                        
                        # Quick Actions (only for individual mode)
                        if not use_global_branches:
                            st.markdown("**🚀 Quick Actions:**")
                            quick_col1, quick_col2, quick_col3, quick_col4 = st.columns(4)
                            
                            with quick_col1:
                                if st.button("🎯 All: dev→main"):
                                    for config in configured_projects:
                                        project_key = f"{config['project']['owner']}/{config['project']['repo']}"
                                        st.session_state.individual_configs[project_key] = {
                                            'source_branch': 'develop',
                                            'dest_branch': 'main'
                                        }
                                    st.rerun()
                            
                            with quick_col2:
                                if st.button("🚀 All: staging→prod"):
                                    for config in configured_projects:
                                        project_key = f"{config['project']['owner']}/{config['project']['repo']}"
                                        st.session_state.individual_configs[project_key] = {
                                            'source_branch': 'staging',
                                            'dest_branch': 'production'
                                        }
                                    st.rerun()
                            
                            with quick_col3:
                                if st.button("🔄 Reset All"):
                                    for config in configured_projects:
                                        project = config['project']
                                        project_key = f"{project['owner']}/{project['repo']}"
                                        st.session_state.individual_configs[project_key] = {
                                            'source_branch': project.get('default_source_branch', 'develop'),
                                            'dest_branch': project.get('default_dest_branch', 'main')
                                        }
                                    st.rerun()
                            
                            with quick_col4:
                                if st.button("📋 Copy Config"):
                                    config_text = "Project Configurations:\n"
                                    for config in configured_projects:
                                        project = config['project']
                                        config_text += f"• {project['name']}: {config['source_branch']} → {config['dest_branch']}\n"
                                    st.text_area("Configuration (copy this):", config_text, height=100)
                        

                        
                        # Validation and bulk check
                        st.markdown("---")
                        
                        # Validate configurations
                        invalid_configs = []
                        valid_configs = []
                        
                        for config in configured_projects:
                            if not config['source_branch'] or not config['source_branch'].strip() or \
                               not config['dest_branch'] or not config['dest_branch'].strip():
                                invalid_configs.append(config['project']['name'])
                            else:
                                valid_configs.append(config)
                        
                        # Show validation status
                        if invalid_configs:
                            st.error(f"❌ Invalid configurations for: {', '.join(invalid_configs)}")
                            st.error("Please ensure all projects have both source and destination branches specified.")
                        
                        if valid_configs:
                            st.success(f"✅ {len(valid_configs)} projects ready for checking")
                        
                        # Bulk check button
                        can_run_check = len(valid_configs) > 0 and (
                            not use_global_branches or (global_source and global_dest)
                        )
                        
                        if st.button("🚀 Check All Projects", 
                                   type="primary", 
                                   disabled=not can_run_check,
                                   help="Start bulk merge status check for all configured projects"):
                            if not github_token:
                                st.error("❌ GitHub token required for private repositories!")
                            else:
                                # Perform bulk check with progress tracking
                                progress_bar = st.progress(0)
                                status_text = st.empty()
                                
                                def update_progress(current, total, project_name):
                                    progress = (current + 1) / total
                                    progress_bar.progress(progress)
                                    status_text.text(f"🔍 Checking {current + 1}/{total}: {project_name}")
                                
                                # Use only valid configurations
                                results = st.session_state.github_checker.bulk_check_projects_with_config(
                                    valid_configs,
                                    progress_callback=update_progress
                                )
                                
                                # Clear progress indicators
                                progress_bar.empty()
                                status_text.empty()
                                
                                # Display results
                                st.header("📊 Bulk Check Results")
                                
                                # Summary statistics
                                total_projects = len(results)
                                merged_projects = len([r for r in results if r['is_merged'] and r['status'] == 'success'])
                                error_projects = len([r for r in results if r['status'] == 'error'])
                                
                                col1, col2, col3, col4 = st.columns(4)
                                with col1:
                                    st.metric("Total Projects", total_projects)
                                with col2:
                                    st.metric("✅ Fully Merged", merged_projects)
                                with col3:
                                    st.metric("⚠️ Need Merge", total_projects - merged_projects - error_projects)
                                with col4:
                                    st.metric("❌ Errors", error_projects)
                                
                                # Detailed results
                                for result in results:
                                    project = result['project']
                                    
                                    with st.expander(f"📁 {project['name']} - {'✅ MERGED' if result['is_merged'] else '⚠️ NEEDS MERGE' if result['status'] == 'success' else '❌ ERROR'}", 
                                                   expanded=not result['is_merged'] or result['status'] == 'error'):
                                        
                                        if result['status'] == 'error':
                                            st.error(f"❌ Error: {result.get('error', 'Unknown error')}")
                                            st.info(f"Repository: {project['owner']}/{project['repo']}")
                                        else:
                                            # Project info
                                            col1, col2 = st.columns(2)
                                            with col1:
                                                st.info(f"**Repository:** {project['owner']}/{project['repo']}")
                                                st.info(f"**Source:** `{result['source_branch']}` → **Destination:** `{result['dest_branch']}`")
                                            
                                            with col2:
                                                st.metric("Commits Ahead", result['commits_ahead'])
                                                if result['comparison']:
                                                    st.metric("Commits Behind", result['commits_behind'])
                                            
                                            # Unmerged commits
                                            if result['commits']:
                                                st.markdown("**📝 Unmerged Commits:**")
                                                commits_df = pd.DataFrame(result['commits'])
                                                st.dataframe(commits_df, use_container_width=True)
                                                
                                                # GitHub links
                                                compare_url = f"https://github.com/{project['owner']}/{project['repo']}/compare/{result['dest_branch']}...{result['source_branch']}"
                                                st.markdown(f"**[📊 View on GitHub]({compare_url})**")
                                            else:
                                                st.success("🎉 All commits merged!")
                                
                                # Export all results
                                if st.button("📄 Export All Results to CSV"):
                                    export_data = []
                                    for result in results:
                                        export_data.append({
                                            'Project': result['project']['name'],
                                            'Repository': f"{result['project']['owner']}/{result['project']['repo']}",
                                            'Source Branch': result['source_branch'],
                                            'Destination Branch': result['dest_branch'],
                                            'Status': 'Merged' if result['is_merged'] else 'Needs Merge' if result['status'] == 'success' else 'Error',
                                            'Commits Ahead': result['commits_ahead'],
                                            'Commits Behind': result['commits_behind'],
                                            'Error': result.get('error', '') if result['status'] == 'error' else ''
                                        })
                                    
                                    export_df = pd.DataFrame(export_data)
                                    csv = export_df.to_csv(index=False)
                                    st.download_button(
                                        label="Download Results CSV",
                                        data=csv,
                                        file_name=f"bulk_merge_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                        mime="text/csv"
                                    )

    # GitHub Repository Mode
    with tab1:
        st.header("🐙 GitHub Repository Analysis")
        
        # GitHub configuration
        with st.expander("🔐 GitHub Configuration", expanded=True):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                github_token = st.text_input(
                    "GitHub Personal Access Token (Optional)",
                    type="password",
                    help="For private repositories or higher rate limits. Leave empty for public repos."
                )
                
                if github_token:
                    st.session_state.github_checker.set_github_token(github_token)
                    st.success("✅ Token configured")
                else:
                    st.info("💡 Without a token, you have limited API calls (60/hour) and can't access private repos")
            
            with col2:
                st.markdown("**Need a token?**")
                st.markdown("[Generate here](https://github.com/settings/tokens)")
                
                # Check rate limits
                if st.button("📊 Check Rate Limits"):
                    success, rate_info = st.session_state.github_checker.check_rate_limit()
                    if success and rate_info:
                        core_limit = rate_info['rate']
                        remaining = core_limit['remaining']
                        limit = core_limit['limit']
                        reset_time = datetime.fromtimestamp(core_limit['reset'])
                        
                        st.metric("API Calls Remaining", f"{remaining}/{limit}")
                        if remaining < 10:
                            st.warning(f"⚠️ Low API calls remaining! Resets at {reset_time.strftime('%H:%M:%S')}")
                        else:
                            st.success(f"✅ Good! Resets at {reset_time.strftime('%H:%M:%S')}")
                    else:
                        st.error("Could not fetch rate limit info")
        
        # Repository URL input
        st.markdown("**Repository URL**")
        repo_url = st.text_input(
            "GitHub Repository URL",
            value="https://github.com/microsoft/vscode",
            placeholder="https://github.com/owner/repo",
            help="Enter the GitHub repository URL"
        )
        
        # Quick examples
        st.markdown("**📂 Try these example repositories:**")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🔥 Microsoft/VSCode"):
                st.session_state.example_repo = "https://github.com/microsoft/vscode"
                st.rerun()
        
        with col2:
            if st.button("⚛️ Facebook/React"):
                st.session_state.example_repo = "https://github.com/facebook/react"
                st.rerun()
        
        with col3:
            if st.button("🐍 Python/CPython"):
                st.session_state.example_repo = "https://github.com/python/cpython"
                st.rerun()
        
        # Use example repo if selected
        if 'example_repo' in st.session_state:
            repo_url = st.session_state.example_repo
            
        # Add note about Phoenix repository
        st.info("💡 **Note**: The Phoenix repository appears to be private. You'll need a GitHub token with access to that organization to use it.")
        
        if repo_url:
            owner, repo = st.session_state.github_checker.parse_github_url(repo_url)
            
            if owner and repo:
                st.success(f"📂 Repository: **{owner}/{repo}**")
                
                # Test connection
                if st.button("🔍 Connect to Repository"):
                    with st.spinner("Testing connection..."):
                        success, result = st.session_state.github_checker.test_github_connection(owner, repo)
                        
                        if success:
                            st.success("✅ Successfully connected to repository!")
                            repo_info = result
                            
                            # Display repository info
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("⭐ Stars", repo_info.get('stargazers_count', 'N/A'))
                            with col2:
                                st.metric("🍴 Forks", repo_info.get('forks_count', 'N/A'))
                            with col3:
                                st.metric("👁️ Watchers", repo_info.get('watchers_count', 'N/A'))
                            
                            st.session_state.github_connected = True
                            st.session_state.github_owner = owner
                            st.session_state.github_repo = repo
                            # Reset branches cache when connecting to new repo
                            st.session_state.branches_loaded = False
                            if 'cached_branches' in st.session_state:
                                del st.session_state.cached_branches
                        else:
                            st.error(f"❌ Connection failed: {result}")
                            st.session_state.github_connected = False
                
                # Branch analysis (only if connected)
                if st.session_state.get('github_connected', False):
                    st.header("🌿 Branch Analysis")
                    
                    # Get branches with better progress indication
                    if st.button("🔄 Load All Branches", type="secondary"):
                        st.session_state.branches_loaded = False
                    
                    if not st.session_state.get('branches_loaded', False):
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        status_text.text("🔍 Fetching branches from GitHub...")
                        progress_bar.progress(25)
                        
                        branches = st.session_state.github_checker.get_github_branches(
                            st.session_state.github_owner, 
                            st.session_state.github_repo
                        )
                        
                        progress_bar.progress(75)
                        status_text.text("📝 Processing branch list...")
                        
                        if branches:
                            st.session_state.cached_branches = branches
                            st.session_state.branches_loaded = True
                            progress_bar.progress(100)
                            status_text.text(f"✅ Loaded {len(branches)} branches successfully!")
                        else:
                            progress_bar.empty()
                            status_text.error("❌ Failed to load branches")
                            return
                    else:
                        branches = st.session_state.get('cached_branches', [])
                    
                    if branches:
                        # Branch filtering info
                        st.success(f"✅ Found {len(branches)} branches in this repository")
                        
                        if len(branches) > 20:
                            st.info(f"💡 Large repository! Use the search filters below to find branches quickly.")
                        
                        # Branch selection
                        st.subheader("🌿 Select Branches to Compare")
                        st.markdown("Choose the **source branch** (contains commits) and **destination branch** (to compare against):")
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Source Branch** (commits from)")
                            
                            # Combined search and select for source
                            with st.container():
                                if len(branches) > 10:
                                    source_search = st.text_input(
                                        "Filter branches:",
                                        placeholder="Type to search...",
                                        key="source_search",
                                        help="Search to filter the dropdown options"
                                    )
                                    
                                    # Filter branches based on search
                                    if source_search:
                                        filtered_source_branches = [b for b in branches if source_search.lower() in b.lower()]
                                        if not filtered_source_branches:
                                            st.warning("No branches match your search")
                                            filtered_source_branches = branches
                                    else:
                                        filtered_source_branches = branches
                                else:
                                    filtered_source_branches = branches
                                
                                source_branch = st.selectbox(
                                    "Choose source branch:",
                                    options=filtered_source_branches,
                                    key="github_source_branch",
                                    help="The branch containing commits to check"
                                )
                        
                        with col2:
                            st.markdown("**Destination Branch** (compare against)")
                            
                            # Combined search and select for destination
                            with st.container():
                                if len(branches) > 10:
                                    dest_search = st.text_input(
                                        "Filter branches:",
                                        placeholder="Type to search...",
                                        key="dest_search",
                                        help="Search to filter the dropdown options"
                                    )
                                    
                                    # Filter branches based on search
                                    if dest_search:
                                        filtered_dest_branches = [b for b in branches if dest_search.lower() in b.lower()]
                                        if not filtered_dest_branches:
                                            st.warning("No branches match your search")
                                            filtered_dest_branches = branches
                                    else:
                                        filtered_dest_branches = branches
                                else:
                                    filtered_dest_branches = branches
                                
                                dest_branch = st.selectbox(
                                    "Choose destination branch:",
                                    options=filtered_dest_branches,
                                    key="github_dest_branch",
                                    help="The branch to compare against (e.g., main, master)"
                                )
                        
                        # Quick actions for common branches
                        if len(branches) > 10:
                            with st.expander("💡 Quick Branch Selection", expanded=False):
                                st.markdown("**Common branches found in this repository:**")
                                common_branches = ['main', 'master', 'develop', 'dev', 'staging', 'production']
                                available_common = [b for b in common_branches if b in branches]
                                
                                if available_common:
                                    st.info(f"Available common branches: {', '.join(available_common)}")
                                    st.markdown("Use the dropdowns above to select from all available branches, or use the search to filter.")
                                else:
                                    st.info("No standard branch names found. Use the search filters above to find your branches.")
                        
                        # Show selected configuration
                        st.markdown("---")
                        st.markdown("**📋 Selected Configuration:**")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.info(f"**Source:** `{source_branch}`")
                        with col2:
                            st.info(f"**Destination:** `{dest_branch}`")
                        
                        if source_branch == dest_branch:
                            st.error("⚠️ Cannot compare a branch with itself! Please select different branches.")
                            
                        # Compare branches
                        if st.button("🔍 Compare Branches", 
                                   type="primary", 
                                   disabled=source_branch == dest_branch,
                                   help=f"Check if commits from '{source_branch}' are merged into '{dest_branch}'"):
                            if source_branch == dest_branch:
                                st.warning("⚠️ Source and destination branches are the same!")
                            else:
                                with st.spinner("Analyzing branches..."):
                                    commits, comparison, error = st.session_state.github_checker.get_commits_between_branches(
                                        st.session_state.github_owner,
                                        st.session_state.github_repo,
                                        source_branch,
                                        dest_branch,
                                        show_errors=True  # Show errors in single repo mode
                                    )
                                    
                                    if error:
                                        st.error(f"❌ Failed to compare branches: {error}")
                                        return
                                    
                                    # Display results
                                    st.header("🔍 GitHub Merge Analysis Results")
                                    
                                    # Summary cards
                                    col1, col2, col3 = st.columns(3)
                                    
                                    with col1:
                                        if not commits:
                                            st.success("✅ **FULLY MERGED**")
                                            st.success("All commits from source branch are present in destination branch")
                                        else:
                                            st.error("❌ **NOT FULLY MERGED**")
                                            st.error(f"{len(commits)} commits are not merged")
                                    
                                    if comparison:
                                        with col2:
                                            st.metric("Commits Ahead", comparison.get('ahead_by', 0))
                                        
                                        with col3:
                                            st.metric("Commits Behind", comparison.get('behind_by', 0))
                                    
                                    # Detailed commit information
                                    if commits:
                                        st.subheader("📝 Unmerged Commits")
                                        
                                        # Display as a table
                                        df = pd.DataFrame(commits)
                                        st.dataframe(df, use_container_width=True)
                                        
                                        # Export option
                                        if st.button("📄 Export to CSV"):
                                            csv = df.to_csv(index=False)
                                            st.download_button(
                                                label="Download CSV",
                                                data=csv,
                                                file_name=f"unmerged_commits_{source_branch}_to_{dest_branch}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                                mime="text/csv"
                                            )
                                        
                                        # Show GitHub URLs
                                        st.subheader("🔗 GitHub Links")
                                        compare_url = f"https://github.com/{st.session_state.github_owner}/{st.session_state.github_repo}/compare/{dest_branch}...{source_branch}"
                                        pr_url = f"https://github.com/{st.session_state.github_owner}/{st.session_state.github_repo}/compare/{dest_branch}...{source_branch}?expand=1"
                                        
                                        col1, col2 = st.columns(2)
                                        with col1:
                                            st.markdown(f"**[📊 View Comparison on GitHub]({compare_url})**")
                                        with col2:
                                            st.markdown(f"**[🔄 Create Pull Request]({pr_url})**")
                                    
                                    else:
                                        st.success("🎉 **Perfect!** All commits from the source branch are already merged into the destination branch.")
                                        
                                        if comparison:
                                            st.info(f"📍 Base commit: `{comparison.get('merge_base_commit', {}).get('sha', 'N/A')[:8]}`")
            else:
                st.error("❌ Invalid GitHub URL format. Please use: https://github.com/owner/repo")
    
    # Local Repository Mode
    with tab2:
        st.header("📁 Local Repository Analysis")
        
        # Repository Configuration
        with st.expander("📁 Repository Configuration", expanded=True):
            # Repository path input
            repo_path = st.text_input(
                "Repository Path",
                value=os.getcwd(),
                help="Enter the path to your Git repository"
            )
        
            if st.button("Validate Repository"):
                if os.path.exists(repo_path):
                    if st.session_state.local_checker.is_git_repository(repo_path):
                        st.success("✅ Valid Git repository!")
                        st.session_state.repo_path = repo_path
                    else:
                        st.error("❌ Not a Git repository!")
                        st.session_state.repo_path = None
                else:
                    st.error("❌ Path does not exist!")
                    st.session_state.repo_path = None
            
            # Fetch latest changes
            if 'repo_path' in st.session_state and st.session_state.repo_path:
                if st.button("Fetch Latest Changes"):
                    with st.spinner("Fetching latest changes..."):
                        success = st.session_state.local_checker.fetch_latest_changes(st.session_state.repo_path)
                    if success:
                        st.success("✅ Fetched latest changes!")
                    else:
                        st.warning("⚠️ Could not fetch changes")
        
        # Main content for local repos
        if 'repo_path' in st.session_state and st.session_state.repo_path:
            repo_path = st.session_state.repo_path
            
            # Get available branches
            with st.spinner("Loading branches..."):
                branches = st.session_state.local_checker.get_branches(repo_path)
        
            if not branches:
                st.error("No branches found or error accessing repository")
                return
            
            # Branch selection
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Source Branch")
                source_branch = st.selectbox(
                    "Select source branch",
                    options=branches,
                    key="local_source_branch",
                    help="The branch you want to check if it's merged"
                )
                
                # Manual input option
                manual_source = st.text_input("Or enter branch name manually:", key="manual_source")
                if manual_source:
                    source_branch = manual_source
            
            with col2:
                st.subheader("Destination Branch")
                dest_branch = st.selectbox(
                    "Select destination branch",
                    options=branches,
                    key="local_dest_branch",
                    help="The branch you want to check against (e.g., main, master, develop)"
                )
                
                # Manual input option
                manual_dest = st.text_input("Or enter branch name manually:", key="manual_dest")
                if manual_dest:
                    dest_branch = manual_dest
            
            # Check merge status button
            if st.button("🔍 Check Merge Status", type="primary"):
                if source_branch == dest_branch:
                    st.warning("⚠️ Source and destination branches are the same!")
                    return
                
                with st.spinner("Analyzing branches..."):
                    # Validate branches exist
                    source_exists = st.session_state.local_checker.check_branch_exists(repo_path, source_branch)
                    dest_exists = st.session_state.local_checker.check_branch_exists(repo_path, dest_branch)
                    
                    if not source_exists:
                        st.error(f"❌ Source branch '{source_branch}' does not exist!")
                        return
                    
                    if not dest_exists:
                        st.error(f"❌ Destination branch '{dest_branch}' does not exist!")
                        return
                    
                    # Get commits not in destination branch
                    unmerged_commits = st.session_state.local_checker.get_commits_not_in_branch(
                        repo_path, source_branch, dest_branch
                    )
                    
                    # Display results
                    st.header("🔍 Local Merge Analysis Results")
                    
                    # Summary cards
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if not unmerged_commits:
                            st.success("✅ **FULLY MERGED**")
                            st.success("All commits from source branch are present in destination branch")
                        else:
                            st.error("❌ **NOT FULLY MERGED**")
                            st.error(f"{len(unmerged_commits)} commits are not merged")
                    
                    with col2:
                        source_count = st.session_state.local_checker.get_branch_commit_count(repo_path, source_branch)
                        st.metric("Source Branch Commits", source_count)
                    
                    with col3:
                        dest_count = st.session_state.local_checker.get_branch_commit_count(repo_path, dest_branch)
                        st.metric("Destination Branch Commits", dest_count)
                    
                    # Detailed commit information
                    if unmerged_commits:
                        st.subheader("📝 Unmerged Commits")
                        
                        detailed_commits = st.session_state.local_checker.get_detailed_commit_info(
                            repo_path, source_branch, dest_branch
                        )
                        
                        if detailed_commits:
                            # Display as a table
                            df = pd.DataFrame(detailed_commits)
                            st.dataframe(df, use_container_width=True)
                            
                            # Export option
                            if st.button("📄 Export to CSV"):
                                csv = df.to_csv(index=False)
                                st.download_button(
                                    label="Download CSV",
                                    data=csv,
                                    file_name=f"unmerged_commits_{source_branch}_to_{dest_branch}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                    mime="text/csv"
                                )
                        
                        # Show git commands for manual merge
                        st.subheader("🔧 Manual Merge Commands")
                        st.code(f"""
# To merge {source_branch} into {dest_branch}:
git checkout {dest_branch}
git pull origin {dest_branch}
git merge {source_branch}
git push origin {dest_branch}

# Or to create a pull request:
git checkout {source_branch}
git push origin {source_branch}
# Then create PR from {source_branch} to {dest_branch}
                        """, language="bash")
                    
                    else:
                        st.success("🎉 **Perfect!** All commits from the source branch are already merged into the destination branch.")
        
        else:
            # Landing page when no repository is selected
            st.info("👆 Please configure a Git repository in the sidebar to get started")
            
            st.markdown("""
            ## How to use this tool:
            
            ### For GitHub Repositories (Remote):
            1. **Select GitHub mode** at the top
            2. **Optional**: Add GitHub token for private repos or higher rate limits
            3. **Enter Repository URL**: Paste the GitHub repository URL
            4. **Connect**: Test connection to the repository
            5. **Select Branches**: Choose source and destination branches
            6. **Compare**: Click "Compare Branches" to analyze
            
            ### For Local Repositories:
            1. **Select Local mode** at the top
            2. **Configure Repository**: Enter path to your local Git repository
            3. **Validate**: Click "Validate Repository" 
            4. **Select Branches**: Choose your source and destination branches
            5. **Analyze**: Click "Check Merge Status"
            
            ## Features:
            
            - 🐙 **GitHub Integration**: Work directly with GitHub repos without cloning
            - 📊 **Compare branches** and see merge status
            - � **Detailed commit information** for unmerged commits
            - 📄 **Export results** to CSV
            - � **Direct GitHub links** for comparison and PR creation
            - 🔧 **Git commands** for manual merging
            - 🔄 **Fetch latest changes** from remote
            - 🌟 **Support for both local and remote repositories**
            
            ## Example Use Cases:
            
            - Check if feature branch is ready to be deleted after merge
            - Verify release branch has all hotfixes merged
            - Ensure development branch includes all feature branches
            - Audit merge status before deployment
            - Compare branches across different GitHub repositories
        """)
    
    # Help & Documentation Tab
    with tab4:
        st.header("📖 Help & Documentation")
        
        # Table of Contents
        st.markdown("""
        ## 📋 Table of Contents
        - [🚀 Getting Started](#getting-started)
        - [🔐 GitHub Token Setup](#github-token-setup)
        - [🎯 Operation Modes](#operation-modes)
        - [📊 Understanding Results](#understanding-results)
        - [🛠️ Troubleshooting](#troubleshooting)
        - [⚙️ Configuration](#configuration)
        """)
        
        # Getting Started
        st.markdown("""
        ## 🚀 Getting Started
        
        This application helps you check branch merge status across GitHub repositories efficiently.
        
        ### ✨ Key Features
        - **🐙 GitHub Repository (Remote)**: Check any GitHub repository without cloning
        - **📁 Local Repository**: Analyze local Git repositories on your machine  
        - **🏢 Bulk Project Check**: Check multiple repositories simultaneously
        - **🔍 Advanced Filtering**: Filter repositories by keywords, language, and stars
        - **📤 CSV Export**: Export results for reporting and analysis
        """)
        
        # GitHub Token Setup
        st.markdown("""
        ## 🔐 GitHub Token Setup
        
        ### Why You Need a Token
        - **Without Token**: 60 requests/hour, public repositories only
        - **With Token**: 5,000 requests/hour, private + public repositories
        
        ### How to Generate a Token
        1. Go to [GitHub Settings > Personal Access Tokens](https://github.com/settings/tokens)
        2. Click **"Generate new token (classic)"**
        3. Select required scopes:
           - `repo` (for private repositories)
           - `read:org` (for organization repositories)
        4. Copy the generated token
        5. Paste it in the app's token configuration section
        
        ### ⚠️ Security Note
        Never share your personal access token. It provides access to your GitHub account.
        """)
        
        # Operation Modes
        st.markdown("""
        ## 🎯 Operation Modes
        
        ### 🐙 GitHub Repository (Remote)
        **Best for**: Checking individual repositories without cloning
        
        **Steps**:
        1. Enter repository URL (e.g., `https://github.com/microsoft/vscode`)
        2. Select source and destination branches
        3. View detailed commit analysis and merge status
        
        **Features**:
        - Real-time branch comparison
        - Commit-by-commit analysis
        - No local cloning required
        
        ### 📁 Local Repository
        **Best for**: Analyzing repositories already on your machine
        
        **Steps**:
        1. Browse and select your local Git repository
        2. Choose branches from available local branches
        3. Get merge status using local Git commands
        
        **Requirements**:
        - Git must be installed on your system
        - Repository must be a valid Git repository
        
        ### 🏢 Bulk Project Check
        **Best for**: Managing multiple repositories at once
        
        **Two Options**:
        
        #### Option A: Configuration File
        1. Create `projects_config.json` with your repositories
        2. Load configuration and start bulk check
        3. Monitor progress and export results
        
        #### Option B: Organization Discovery  
        1. Enter GitHub organization name
        2. Optionally filter by keyword (minimum 3 characters)
        3. Select repositories and configure branches
        4. Run bulk analysis
        
        **Filtering Examples**:
        - Keyword `"api"` → finds `user-api`, `payment-API`, `API-Gateway`
        - Keyword `"frontend"` → finds `react-frontend`, `Frontend-App`
        - No keyword → fetches all organization repositories
        """)
        
        # Understanding Results
        st.markdown("""
        ## 📊 Understanding Results
        
        ### Status Indicators
        - **✅ Up to date**: No commits to merge, branches are synchronized
        - **⬆️ X commits ahead**: Source branch has X new commits to merge
        - **⬇️ X commits behind**: Source branch is missing X commits from destination  
        - **⚠️ X behind, Y ahead**: Branches diverged - potential merge conflicts
        - **❌ Error**: Connection, permission, or repository access issue
        
        ### Commit Information
        When branches are ahead, you'll see:
        - **Hash**: Short commit identifier (first 8 characters)
        - **Author**: Person who made the commit
        - **Date**: When the commit was made
        - **Message**: First line of the commit message
        
        ### Export Options
        - **📤 Download CSV**: Export results for external analysis
        - **📋 Copy Results**: Copy formatted results to clipboard
        """)
        
        # Troubleshooting
        st.markdown("""
        ## 🛠️ Troubleshooting
        
        ### Common Issues & Solutions
        
        #### "HTTP 404 - Repository not found"
        **Possible Causes**:
        - Repository is private and you don't have access
        - Repository name is incorrect
        - Organization doesn't exist
        
        **Solutions**:
        - Verify repository exists and URL is correct
        - Add GitHub token for private repository access
        - Check organization permissions
        
        #### "HTTP 403 - Access forbidden"  
        **Possible Causes**:
        - Insufficient token permissions
        - Token has expired
        - Organization access restrictions
        
        **Solutions**:
        - Generate new token with `repo` and `read:org` scopes
        - Verify token hasn't expired (check GitHub settings)
        - Request organization access from admin
        
        #### "Branch not found"
        **Possible Causes**:
        - Branch name is misspelled
        - Branch doesn't exist in repository
        - Branch was deleted or renamed
        
        **Solutions**:
        - Use branch dropdown to see available branches
        - Verify branch exists in the repository
        - Check if branch was renamed or merged
        
        #### Rate Limit Exceeded
        **Cause**: Too many API requests
        
        **Solutions**:
        - Add GitHub token for higher rate limits (60/hour → 5,000/hour)
        - Use **"📊 Check Rate Limits"** to monitor usage
        - Wait for rate limit reset (shown in rate limit check)
        
        ### Performance Tips
        1. **Use Keywords**: Filter repositories during discovery to reduce API calls
        2. **Configure Token**: Essential for private repos and higher rate limits  
        3. **Batch Operations**: Use bulk check instead of individual repository checks
        4. **Export Results**: Save results as CSV for offline analysis
        """)
        
        # Configuration  
        st.markdown("""
        ## ⚙️ Configuration
        
        ### Project Configuration File Format
        Create a `projects_config.json` file in your project directory:
        
        ```json
        {
          "projects": [
            {
              "name": "Frontend Application",
              "owner": "mycompany",
              "repo": "frontend-app", 
              "description": "React-based frontend",
              "default_source_branch": "develop",
              "default_dest_branch": "main"
            },
            {
              "name": "API Service",
              "owner": "mycompany",
              "repo": "api-service",
              "description": "Node.js API backend", 
              "default_source_branch": "staging",
              "default_dest_branch": "production"
            }
          ]
        }
        ```
        
        ### Configuration Fields
        - **name**: Display name for the project
        - **owner**: GitHub username or organization name
        - **repo**: Repository name
        - **description**: Optional project description
        - **default_source_branch**: Branch to check (e.g., develop, feature)
        - **default_dest_branch**: Target branch (e.g., main, production)
        
        ### Organization Discovery Settings
        - **Keyword Filter**: Minimum 3 characters, case-insensitive matching
        - **Language Filter**: Filter by programming language
        - **Star Filter**: Minimum number of GitHub stars
        - **Sort Options**: Updated, name, stars, or repository size
        """)
        
        # Contact and Support
        st.markdown("""
        ## 📞 Support & Feedback
        
        ### Need Help?
        1. Check the troubleshooting section above
        2. Verify your GitHub token permissions
        3. Test with a known public repository first
        4. Check repository access rights
        
        ### Tips for Success
        - Start with public repositories to test functionality
        - Use organization discovery with keywords for large organizations  
        - Export results regularly for record-keeping
        - Monitor API rate limits when doing bulk operations
        
        ---
        
        **Happy Branch Checking! 🚀**
        
        *This tool helps streamline branch management across multiple repositories, 
        making it easier to track merge status and maintain code quality.*
        """)

if __name__ == "__main__":
    main()