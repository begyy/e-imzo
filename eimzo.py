import requests
import xmltodict
import json


class Eimzo:
    def __init__(self, pkcs7_url='http://127.0.0.1:9090/dsvs/pkcs7/v1'):
        self.pkcs7_url: str = pkcs7_url
        self.headers: dict = {'content-type': 'text/xml'}

    def verify_pkcs7(self, pkcs7: str) -> bool:
        xml_response_data: str = f"""
        <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
            <Body>
                <verifyPkcs7 xmlns="http://v1.pkcs7.plugin.server.dsv.eimzo.yt.uz/">
                    <pkcs7B64 xmlns="">{pkcs7}</pkcs7B64>
                </verifyPkcs7>
            </Body>
        </Envelope>
        """
        response = requests.post(self.pkcs7_url, data=xml_response_data, headers=self.headers)
        result = response.text
        json_format = self.pars_xml_to_json(result)
        check_result: bool = self.check_verify_pkcs7(json_format)
        return check_result

    def check_verify_pkcs7(self, data: dict) -> bool:
        response_result = data['S:Envelope']['S:Body']['ns2:verifyPkcs7Response']['return']
        response_result = json.loads(response_result)
        if response_result['success'] is False:
            return False

        response_result = response_result['pkcs7Info']['signers'][0]
        if response_result['verified'] is False:
            return False
        if response_result['certificateVerified'] is False:
            return False
        if response_result['certificateValidAtSigningTime'] is False:
            return False
        return True

    def pars_xml_to_json(self, xml_text: str) -> dict:
        dump = json.dumps(xmltodict.parse(xml_text))
        load: dict = json.loads(dump)
        return load
