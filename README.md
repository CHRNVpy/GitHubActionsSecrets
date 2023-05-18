<h1> GitHub Actions Secrets</h1>

<h3>Usage example</h3>
<p>define your repo_url and token<br>
<code>github_url = 'GITHUB_URL'  # https://github.com/OWNER_NAME/REPO_NAME</code><br>
<code>token = 'YOUR_GITHUB_TOKEN'</code>
</p>

<p>create an instance of GitHubSecret<br>
<code>secret = GitHubSecret(github_url, token=token)</code>
</p>

<p>now u can use GitHubSecret methods to list, get, create/update your secrets<br>
<code>secret.list_secrets()</code><br>
<code>secret.get_secret()</code><br>
<code>secret.create_update_secret('SECRET_NAME', 'SECRET_VALUE')</code><br>
</p>
