# coding=utf-8
"""
Template emails for account maintence activities.
"""

open_tag = """<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">"""

html_template = """
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html>
        <head>
            <meta name="viewport" content="width=device-width">
            <meta http-equiv="Content-Type" content="text/html charset=UTF-8" />
        </head>
        <body>
            <table border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" id="bodyTable" style="background-color: #E0E0E0;">
                <tr>
                    <td align="center" valign="top">
                        <table border="0" cellpadding="10" cellspacing="0" width="600" id="emailContainer">
                            <tr>
                                <td align="center" valign="top">
                                    <table border="0" cellpadding="20" cellspacing="0" width="100%" id="emailHeader">
        
                                    </table>
                                </td>
                            </tr>
                            <tr>
                                <td align="center" valign="top">
                                    <table border="0" cellpadding="20" cellspacing="0" width="100%" id="emailBody" style="background-color: #ffffff;">
                                        <tr>
                                            <td align="center" valign="top" id="m_4393282051944905389m_-5269006104307297584templateHeader">
                                                <img src="https://scixplorer.org/styles/img/newsletter-banner.jpg" style="max-width: 100%; height: auto;"/>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td align="left" valign="top">
                                                {msg}
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                            <tr>
                                <td align="center" valign="top">
                                    <table border="0" cellpadding="20" cellspacing="0" width="100%" id="emailFooter" style="color: #999999; font-size: 12px; text-align: center; font-family: sans-serif;">
                                        <tr>
                                            <td align="center" valign="top">
                                                <p> This message was sent to {email_address}. </p>
                                                <p> &copy; SAO/NASA <a href="https://ui.adsabs.harvard.edu">Astrophysics Data System</a> <br> 60 Garden Street <br> Cambridge, MA</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
    </html>
    """


# html_template = """
#     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
#     <html>
#         <head>
#             <meta name="viewport" content="width=device-width">
#             <meta http-equiv="Content-Type" content="text/html charset=UTF-8" />
#             <style type="text/css">
#                 @media only screen and (max-width: 480px){{
#                     #templateColumns{{
#                         width:100% !important;
#                     }}

#                     .templateColumnContainer{{
#                         display:block !important;
#                         width:100% !important;
#                     }}

#                     .columnContent{{
#                         font-size:16px !important;
#                         line-height:125% !important;
#                     }}

#                     .leftColumnContent{{
#                         font-size:16px !important;
#                         line-height:125% !important;
#                     }}

#                     .rightColumnContent{{
#                         font-size:16px !important;
#                         line-height:125% !important;
#                     }}

#                     h2, h3 {{
#                         font-size: 100%
#                     }}
#                 }}
#                 @media screen and (prefers-color-scheme: dark) {{
#                     a {{
#                         color: #FFFFFF;
#                     }}

#                     body {{
#                         background-color: #2d3239;
#                     }}
#                 }}
#             </style>
#         </head>
#         <body>
#             <table border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" id="bodyTable" style="background-color: #FFFFFF;">
#                 <tr>
#                     <td align="center" valign="top">
#                         <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 1024px;" id="emailContainer" >
#                             <tr>
#                                 <td align="center" valign="top" style="font-family:Arial;">
#                                     <table border="0" cellpadding="0" cellspacing="0" width="100%" id="emailBody" >
#                                         <tr>
#                                             <td align="center" valign="top" id="m_4393282051944905389m_-5269006104307297584templateHeader">
#                                                 <img src="https://scixplorer.org/styles/img/newsletter-banner.jpg" style="max-width: 100%; height: auto;"/>
#                                             </td>
#                                         </tr>
#                                         <tr>
#                                             <td align="center" valign="top" style="width:100%;">
#                                                 &nbsp;
#                                             </td>
#                                         </tr>
#                                         <tr>
#                                             <td align="center" style="width:100%; font-size: 14px; font-family:Arial">
#                                                 {msg}
#                                             </td>
#                                         </tr>
#                                     </table>
#                                 </td>
#                             </tr>
#                             <tr>
#                                 <td align="center" valign="top">
#                                     <table border="0" cellpadding="20" cellspacing="0" width="100%" id="emailFooter" style="color: #999999; font-size: 12px; text-align: center; font-family: sans-serif;">
#                                         <tr>
#                                             <td align="center" valign="top">
#                                                 <p> This message was sent to {email_address}. </p>
#                                                 <p> &copy; SAO/NASA <a href="https://ui.adsabs.harvard.edu">Astrophysics Data System</a> <br> 60 Garden Street <br> Cambridge, MA</p>
#                                             </td>
#                                         </tr>
#                                     </table>
#                                 </td>
#                             </tr>
#                         </table>
#                     </td>
#                 </tr>
#             </table>
#         </body>
#     </html>
#     """


class EmailTemplate(object):
    """
    Data structure that contains email content data
    """

    msg_plain = ""
    msg_html = ""
    subject = ""


class PasswordResetEmail(EmailTemplate):
    msg_plain = """Hi,

You’ve recently requested to reset your password for the NASA ADS account associated with this email address. 
Copy and paste the link below into your browser to reset it. 

{endpoint}

This link is valid only for a limited time.

If you didn't request this, you can safely ignore this email.

- the ADS team
    """
    msg = """{open_tag}Hi,</p>

{open_tag}You've recently requested to reset your password for the <a href="{ui_url}">{ui_env}</a> 
account associated with this email address. Click the link below to reset it:</p>

{open_tag}<a href="{endpoint}">{endpoint}</a></p>

{open_tag}This link is valid only for a limited time.</p>

{open_tag}If you didn't request this, you can safely ignore this email.</p>

{open_tag}- the ADS team</p>""".format(
        open_tag=open_tag, endpoint="""{endpoint}""",ui_url="""{ui_url}""",ui_env="""{ui_env}"""
    )
    msg_html = html_template.format(msg=msg, email_address="""{email_address}""")
    subject = "[{ui_env}] Password reset"


class WelcomeVerificationEmail(EmailTemplate):
    msg_plain = """Hi,

Welcome to the {ui_env}! To finish setting up your account, please confirm your email address by copying and 
pasting the link below into your browser:

{endpoint}

This link is valid only for a limited time.

If you didn't request this, you can safely ignore this email.

- the ADS team
    """

    msg = """{open_tag}Hi,</p>

{open_tag}Welcome to <a href="{ui_url}">{ui_env}</a>! To finish setting up your account, 
please confirm your email address:</p>

{open_tag}<a href="{endpoint}">{endpoint}</a></p>

{open_tag}This link is valid only for a limited time.</p>

{open_tag}If you didn't request this, you can safely ignore this email.</p>

{open_tag}- the ADS team</p>""".format(
        open_tag=open_tag, endpoint="""{endpoint}""", ui_url="""{ui_url}""", ui_env="""{ui_env}"""
    )
    msg_html = html_template.format(msg=msg, email_address="""{email_address}""")
    subject = "[{ui_env}] Please verify your email address"


class VerificationEmail(EmailTemplate):
    msg_plain = """Hi,

You've recently requested to change the email address associated with your {ui_env} account. To confirm this change, 
please copy and paste the link below into your browser:

{endpoint}

This link is valid only for a limited time.

If you didn't request this, you can safely ignore this email.

- the ADS team
    """

    msg = """{open_tag}Hi,</p>

{open_tag}You've recently requested to change the email address associated with your 
<a href="{ui_url}">{ui_env}</a> account. To confirm this change, please click the link below:</p>

{open_tag}<a href="{endpoint}">{endpoint}</a></p>

{open_tag}This link is valid only for a limited time.</p>

{open_tag}If you didn't request this, you can safely ignore this email.</p>

{open_tag}- the ADS team</p>""".format(
        open_tag=open_tag, endpoint="""{endpoint}""", ui_url="""{ui_url}""", ui_env="""{ui_env}"""
    )
    msg_html = html_template.format(msg=msg, email_address="""{email_address}""")
    subject = "[{ui_env}] Please verify your email address"


class EmailChangedNotification(EmailTemplate):
    msg_plain = """Hi,

You’ve recently requested to change the email address associated with your {ui_env} account.

A verification email has been sent to the new email address. After the new email address has been confirmed, 
this email address will no longer be associated with your account.

If you didn't request this, please reply to this email, or contact the support team at adshelp@cfa.harvard.edu directly.

- the ADS team"""

    msg = """{open_tag}Hi,</p>

{open_tag}You’ve recently requested to change the email address associated with your 
<a href="{ui_url}">{ui_env}</a> account. </p>

{open_tag}A verification email has been sent to the new email address. After the new email address has been confirmed, 
this email address will no longer be associated with your account.</p>

{open_tag}If you didn't request this, please reply to this email, or contact the 
<a href="mailto:adshelp@cfa.harvard.edu">support team</a> directly.</p>

{open_tag}- the ADS team</p> """.format(
        open_tag=open_tag, ui_url="""{ui_url}""", ui_env="""{ui_env}"""
    )

    msg_html = html_template.format(msg=msg, email_address="""{email_address}""")
    subject = "[{ui_env}] An email change has been requested"


class AccountRegistrationAttemptEmail(EmailTemplate):
    msg_plain = """Hi,

We noticed an attempt to register a {ui_env} account using your email address. If this was you, please disregard this message.

If you did not initiate this registration, please ensure your email account is secure and consider changing your password.

If you are an existing ADS user attempting to use SciX, please know that ADS and SciX share the same backend so your existing ADS account and password will also work on SciX.

If you have any questions or need further assistance, please reply to this email, or contact the support team at adshelp@cfa.harvard.edu directly.

- the ADS team"""

    msg = """{open_tag}Hi,</p>

{open_tag}We noticed an attempt to register a <a href="{ui_url}">{ui_env}</a> account associated with this email address. </p>

{open_tag}If you did not initiate this registration, please ensure your email account is secure and consider changing your password.</p>

{open_tag}If you are an existing ADS user attempting to use SciX, please know that ADS and SciX share the same backend so your existing ADS account and password will also work on SciX.</p>

{open_tag}If you have any questions or need further assistance, please reply to this email, or contact the <a href="mailto:adshelp@cfa.harvard.edu">support team</a> directly.</p>


{open_tag}- the ADS team</p>""".format(
        open_tag=open_tag, ui_url="""{ui_url}""", ui_env="""{ui_env}"""
    )
    msg_html = html_template.format(msg=msg, email_address="""{email_address}""")
    subject = "[{ui_env}] Account Registration Attempt Notice"
