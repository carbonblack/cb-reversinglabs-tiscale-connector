from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisInProgress, AnalysisResult,
                                                    AnalysisTemporaryError, AnalysisPermanentError)
from cbapi.connection import CbAPISessionAdapter
from cbint.utils import feed

import logging
from datetime import datetime
from requests import Session

from .tiscale_client import TiScaleClient

log = logging.getLogger(__name__)

class ReversingLabsTiScaleProvider(BinaryAnalysisProvider):
    def __init__(self, name, api_token, base_url, log_level, submit_full_binaries):
        super(ReversingLabsTiScaleProvider, self).__init__(name)

        session = Session()
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        session.mount("https://", tls_adapter)

        self.base_url = base_url
        self.log_level = log_level
        self.submit_full_binaries = submit_full_binaries

        if log_level:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)

        self.tiscale_client = TiScaleClient(session=session,
                                            base_url=self.base_url,
                                            api_token=api_token,
                                            log_level=self.log_level
                                            )

    def make_result(self, md5sum, uploaded=False):
        if not uploaded:
            raise AnalysisTemporaryError(message="Hash is not yet uploaded to TitaniumScale", retry_in=30*60)

        malware_result = "File {} uploaded to TitaniumScale, date: {}".format(md5sum, datetime.utcnow())
        return AnalysisResult(message=malware_result,
                              extended_message=malware_result,
                              link="Result should be stored in Splunk",
                              score=20)

    def check_result_for(self, md5sum):
        pass

    def analyze_binary(self, md5sum, binary_file_stream):
        if not self.submit_full_binaries:
            raise AnalysisPermanentError(message="NOT SUBMITTING FULL BINARIES")

        response = self.tiscale_client.upload_file(md5sum=md5sum, binary_file_stream=binary_file_stream )

        if response.status_code == 200:
            log.info("File {} uploaded successfully. Response status_code = {}".format(md5sum, response.status_code))
            return self.make_result(md5sum=md5sum, uploaded=True)

        elif response.status_code == 403:
            log.info("Quota reached. Response status_code: {}".format(response.status_code))
            raise AnalysisTemporaryError(message="Quota reached, will retry in 1 hour", retry_in=60*60)

        else:
            log.info("Unable to upload file. Response status_code: {}".format(response.status_code))
            raise AnalysisTemporaryError(message="Uploading file failed, will try again in 30 min", retry_in=30*60)


class ReversingLabsTiScaleConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('orig_mod_len:[1 TO {}]'.format(max_module_len))
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return " ".join(filters)

    @property
    def integration_name(self):
        return 'Cb ReversingLabs TiScale connector 1.0'

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("reversinglabs_quick_scan_threads", 0)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("reversinglabs_deep_scan_threads", 2)

    def get_provider(self):
        tiscale_provider = ReversingLabsTiScaleProvider(name=self.name,
                                                        api_token=self.tiscale_api_token,
                                                        base_url=self.tiscale_base_url,
                                                        log_level=self.log_level,
                                                        submit_full_binaries=self.submit_full_binaries
                                                        )

        return tiscale_provider

    def get_metadata(self):

        return feed.generate_feed(self.name,
                                  summary="The ReversingLabs TitaniumScale Appliance is powered by TitaniumCore, the malware analysis engine that performs automated static analysis using the Active File Decomposition technology.TitaniumCore unpacks and recursively analyzes files without executing them, and extracts internal threat indicators to classify files and determine their threat level. TitaniumCore is capable of identifying thousands of file format families. It recursively unpacks hundreds of file format families, and fully repairs extracted files to enable further analysis.",
                                  tech_data="A ReversingLabs private API key is required to use this feed. There are no requirements to share any data with Carbon Black or ReversingLabs to use this feed. However, binaries may be shared with ReversingLabs.",
                                  provider_url="https://reversinglabs.com",
                                  icon_path="/usr/share/cb/integrations/reversinglabs-tiscale/rl-titaniumscale.png",
                                  display_name='ReversingLabs - TitaniumScale',
                                  category='Connector'
                                  )

    def validate_config(self):
        super(ReversingLabsTiScaleConnector, self).validate_config()

        self.check_required_options([
            "reversinglabs_tiscale_host",
            "carbonblack_server_token"
        ])

        self.tiscale_api_token = self.get_config_string("tiscale_api_token", None)
        self.callback_url = self.get_config_string("tiscale_callback_url", None)
        self.tiscale_base_url = self.get_config_string("reversinglabs_tiscale_host", None)

        log.info("Validate config, type of tiscale_base_url: {}".format(type(self.tiscale_base_url)))
        self.submit_full_binaries = self.get_config_string("submit_full_binaries", "true")
        self.submit_full_binaries = True if self.submit_full_binaries.lower() in ['true', '1'] else False

        self.log_level = logging.DEBUG if int(self.get_config_string("debug", 0)) is 1 else logging.INFO
        log.setLevel(self.log_level)

        return True


if __name__ == "__main__":
    import os

    my__path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/reversinglabs"

    config_path = os.path.join(my__path, "testing.conf")
    deamon = ReversingLabsTiScaleConnector(name="reversinglabstiscale",
                                    configfile=config_path,
                                    work_directory=temp_directory,
                                    logfile=os.path.join(temp_directory, 'test.log'),
                                    debug=True)

    logging.getLogger().setLevel(logging.DEBUG)

    deamon.start()
