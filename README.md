# Function Calling Extensions Sample

> [!NOTE]
> To use Copilot Extensions, you must be enrolled in the limited public beta.
> 
> All enrolled users with a GitHub Copilot Individual subscription can use Copilot Extensions.
> 
> For enrolled organizations or enterprises with a Copilot Business or Copilot Enterprise subscription, organization owners and enterprise administrators can grant access to Copilot Extensions.

## Description
This project is a Go application that demonstrates how to use function calling in a GitHub Copilot Extension.

## Prerequisites

- Go 1.16 or higher
- Set the following environment variables (example below):

```
export PORT=8080
export CLIENT_ID=Iv1.0ae52273ad3193eb // the application id
export CLIENT_SECRET="your_client_secret" // generate a new client secret for your application
export FQDN=https://6de513480979.ngrok.app // use ngrok to expose a url
```

## Installation:
1. Clone the repository: 

```
git clone git@github.com:copilot-extensions/function-calling-extension.git
cd function-calling-extension
```

2. Install dependencies:

```
go mod tidy
```

## Usage

1. Start up ngrok with the port provided:

```
ngrok http http://localhost:8080
```

2. Set the environment variables (use the ngrok generated url for the `FDQN`)
3. Run the application:

```
go run .
```

## Accessing the Agent in Chat:

1. In the `Copilot` tab of your Application settings (`https://github.com/settings/apps/<app_name>/agent`)
- Set the URL that was set for your FQDN above with the endpoint `/agent` (e.g. `https://6de513480979.ngrok.app/agent`)
- Set the Pre-Authorization URL with the endpoint `/auth/authorization` (e.g. `https://6de513480979.ngrok.app/auth/authorization`)
2. In the `General` tab of your application settings (`https://github.com/settings/apps/<app_name>`)
- Set the `Callback URL` with the `/auth/callback` endpoint (e.g. `https://6de513480979.ngrok.app/auth/callback`)
- Set the `Homepage URL` with the base ngrok endpoint (e.g. `https://6de513480979.ngrok.app/auth/callback`)
3. Ensure your permissions are enabled in `Permissions & events` > 
- `Repository Permissions` > `Issues` > `Access: Read and Write`
- `Account Permissions` > `Copilot Chat` > `Access: Read Only`
4. Ensure you install your application at (`https://github.com/apps/<app_name>`)
5. Now if you go to `https://github.com/copilot` you can `@` your agent using the name of your application.

## What Can It Do

Test out the agent with the following commands!

| Description | Prompt |
| --- |--- |
| User asking `@agent` to create a GitHub issue | `@agent Create an issue in the repo (org/repo) with title "my first issue" and body "hooray I created an issue"` |
| User asking `@agent` to list GitHub issues | `@agent list all issues in this repo (org/repo)` |
