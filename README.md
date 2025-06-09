# PyMTA-server
Python Email server for sending emails directly to recipient ( no email Relay)
```bash
# Testing
.venv/bin/python app.py --web-only --debug
# Production:
python app.py --smtp-only & gunicorn -w 4 -b 0.0.0.0:5000 app:flask_app
```
## Plan:
- make full python MTA server with front end to allow sending any email
- include DKIM
- optional storing send emails
- provide required details to update DNS records like SPF, DKIM for email delivery success
- Allow sending emails using Username and password, or by whitelisting the Sender IP

## Tests - examples
[CLI commands and usage example](./tests/general_cli_usage.md)

[Send Test Emails examples](./tests/run_tests_manually.md)


## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).  
See the [LICENSE](./LICENSE) file for more information.