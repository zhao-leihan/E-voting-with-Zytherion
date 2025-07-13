import requests

class MailJetAPI:
    def __init__(self, api_key, api_secret):
        """
        Initialize the MailJet API with API key and secret.
        :param api_key: MailJet API key.
        :param api_secret: MailJet API secret.
        """
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://api.mailjet.com/v3.1/send"  # Base URL for sending emails

    def send_email(self, recipient_email, subject, recipient_name, nim, dob, tx_hash):
        """
        Send an email using the MailJet API.
        :param recipient_email: Email address of the recipient.
        :param subject: Subject of the email.
        :param recipient_name: Name of the recipient.
        :param nim: Student ID (NIM) of the recipient.
        :param dob: Date of Birth (DoB) of the recipient.
        :param tx_hash: Transaction hash (TX Hash) to be sent.
        :return: True if email is sent successfully, False otherwise.
        """
        # Construct the email message
        message = f"""
        Dear {recipient_name},

        Thank you for using our E-Voting System.

        Below are your registration details:
        - Name: {recipient_name}
        - NIM: {nim}
        - Date of Birth: {dob}

        Your transaction hash (TX Hash) is: **{tx_hash}**

        Please keep this information secure. It will be required to verify your account.

        If you did not request this email, please ignore it.

        Best regards,  
        **E-Voting System Team**
        """

        # Prepare the payload for the API request
        data = {
            "Messages": [
                {
                    "From": {"Email": "Your Email", "Name": "E-Voting System"},
                    "To": [{"Email": recipient_email, "Name": recipient_name}],
                    "Subject": subject,
                    "TextPart": message,
                    "HTMLPart": f"""
                    <h3>Dear {recipient_name},</h3>
                    <p>Thank you for using our E-Voting System.</p>
                    <p>Below are your registration details:</p>
                    <ul>
                        <li><strong>Name:</strong> {recipient_name}</li>
                        <li><strong>NIM:</strong> {nim}</li>
                        <li><strong>Date of Birth:</strong> {dob}</li>
                    </ul>
                    <p>Your transaction hash (TX Hash) is: <strong>{tx_hash}</strong></p>
                    <p>Please keep this information secure. It will be required to verify your account.</p>
                    <p>If you did not request this email, please ignore it.</p>
                    <p>Best regards,<br><strong>E-Voting System Team</strong></p>
                    """
                }
            ]
        }

        # Set headers and authentication
        headers = {"Content-Type": "application/json"}
        auth = (self.api_key, self.api_secret)

        try:
            # Send the POST request to MailJet API
            response = requests.post(self.base_url, headers=headers, auth=auth, json=data)
            response.raise_for_status()  # Raise an exception for HTTP errors
            print("Email sent successfully!")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to send email: {e}")
            return False
        
        
    def send_Transaction(self, recipient_email, subject, voter_name, voter_tx_hash, candidate_number, candidate_name, tx_hash):
        """
        Send an email using the MailJet API after a successful transaction.
        :param recipient_email: Email address of the voter.
        :param subject: Subject of the email.
        :param voter_name: Name of the voter.
        :param voter_tx_hash: Transaction hash (TX Hash) of the voter.
        :param candidate_number: Candidate number that the voter selected.
        :param candidate_name: Name of the candidate that the voter selected.
        :param tx_hash: Transaction hash (TX Hash) of the vote.
        :return: True if email is sent successfully, False otherwise.
        """
        # Construct the email message
        message = f"""
        Dear {voter_name},

        Congratulations! You have successfully cast your vote in the E-Voting System.

        Below are the details of your vote:
        - Voter Name: {voter_name}
        - Voter TX Hash: {voter_tx_hash}
        - Candidate Number: {candidate_number}
        - Candidate Name: {candidate_name}
        - Transaction Hash (TX Hash): {tx_hash}

        Please keep this information secure. It serves as proof of your participation in the election.

        If you did not initiate this action, please contact our support team immediately.

        Best regards,  
        **E-Voting System Team**
        """

        # Prepare the payload for the API request
        data = {
            "Messages": [
                {
                    "From": {"Email": "evotersverify@gmail.com", "Name": "E-Voting System"},
                    "To": [{"Email": recipient_email, "Name": voter_name}],
                    "Subject": subject,
                    "TextPart": message,
                    "HTMLPart": f"""
                    <h3>Dear {voter_name},</h3>
                    <p>Congratulations! You have successfully cast your vote in the E-Voting System.</p>
                    <p>Below are the details of your vote:</p>
                    <ul>
                        <li><strong>Voter Name:</strong> {voter_name}</li>
                        <li><strong>Voter TX Hash:</strong> {voter_tx_hash}</li>
                        <li><strong>Candidate Number:</strong> {candidate_number}</li>
                        <li><strong>Candidate Name:</strong> {candidate_name}</li>
                        <li><strong>Transaction Hash (TX Hash):</strong> {tx_hash}</li>
                    </ul>
                    <p>Please keep this information secure. It serves as proof of your participation in the election.</p>
                    <p>If you did not initiate this action, please <a href="mailto:support@evoting.com">contact our support team</a> immediately.</p>
                    <p>Best regards,<br><strong>E-Voting System Team</strong></p>
                    """
                }
            ]
        }

        # Set headers and authentication
        headers = {"Content-Type": "application/json"}
        auth = (self.api_key, self.api_secret)

        try:
            # Send the POST request to MailJet API
            response = requests.post(self.base_url, headers=headers, auth=auth, json=data)
            response.raise_for_status()  # Raise an exception for HTTP errors
            print("Email sent successfully!")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to send email: {e}")
            return False
