import logging
import os

from urlparse import urljoin

log = logging.getLogger(__name__)


class TiScaleClient(object):
    def __init__(self, session, base_url, api_token, log_level):

        self.session = session
        self.base_url = base_url
        self.api_token = api_token
        self.log_level = log_level

        if log_level:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)

    def get_hash_report(self):
        pass

    def check_hash_report(self):
        pass

    def upload_file(self, md5sum, binary_file_stream):
        upload_url = 'upload'

        request_url = urljoin(self.base_url, upload_url)

        log.error('request url: {}'.format(request_url))
        file_name = None
        if hasattr(binary_file_stream, "name"):
            log.info("submitting file: fs.name: %s" % binary_file_stream.name)
            file_name = os.path.basename(binary_file_stream.name)

        headers = None
        if self.api_token:
            headers = {"Authorization": "Token %s" % self.api_token}

        files = {"file": (file_name, open(file_name, 'rb'))} if file_name else {"file": (md5sum, binary_file_stream)}

        response = self.session.post(request_url, files=files, headers=headers, verify=False)

        return response
