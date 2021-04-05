# What is it?
This is a LINE Login sample created by Haimin. 


# How to run
## Run on Heroku
### Requirement
- A LINE Login channel with the "WEB" app type. To create a channel, go to [Creating a Channel](https://developers.line.me/web-api/channel-registration) on the LINE Developers site.
- A [Heroku](https://dashboard.heroku.com/) account (free to create)

### Deploy the app on Heroku

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/hamyco/line_login_python_sample)

With the "Deploy to Heroku" button, you can easily deploy the LINE Login starter application to Heroku from your web browser by following the steps below.

1. Click the **Deploy to Heroku** button to go to the Heroku Dashboard to configure and deploy the app.
2. Enter a Heroku app name (optional).
3. Enter the following Heroku config variables.
    - **Channel ID:** Found in the "Channel settings" page in the [console](https://developers.line.me/console/)
    - **Channel secret:** Found in the "Channel settings" page in the [console](https://developers.line.me/console/)
4. Click the **Deploy** button. Heroku then deploys this repository to a new Heroku app on your account.

## Run on Local
### Requirement
 - Python3
 - Libraries which written on requirement.txt

### Launch program on local
 - Change the value of run.sh
   - Change the channel ID of **Your_Channel_ID**
   - Change the channel ID of **Your_Channel_SECRET**
 - Execute the following command on Terminal
``` 
cd [THE_PROJECT_PATH]
bash run.sh
  ```

