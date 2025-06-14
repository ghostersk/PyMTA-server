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

![image](https://github.com/user-attachments/assets/4ec1ed38-ca16-4d77-8836-705e554bdf29)
![image](https://github.com/user-attachments/assets/333e284a-33c8-4a7e-8cb3-f98438f03c80)
![image](https://github.com/user-attachments/assets/d10864f6-4b3a-4e92-8d85-19cfb630d960)
![image](https://github.com/user-attachments/assets/7d9b7a3f-b5df-4d2c-ac47-f9544059bd86)
![image](https://github.com/user-attachments/assets/258f4f82-9859-4666-a8b6-5f6025311057)
![image](https://github.com/user-attachments/assets/8e79005a-e034-4663-9b5e-c17ca735fee5)


## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).  
See the [LICENSE](./LICENSE) file for more information.
