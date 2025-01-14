import json
import logging
import sys
from typing import Dict, List

import boto3

logger = logging.getLogger(__name__)


class GetAvailableCIDRs:
    """
    Returns two available CIDRs for new environment
    """

    def __init__(self, dynamo_table: str = "cf-environments-mapping", region_name: str = "us-east-1") -> None:
        """
        :param dynamo_table: Dynamo DB table name
        :param region_name: AWS region name
        """
        self.dynamo_table = dynamo_table
        self.region_name = region_name
        dev_session = boto3.Session(profile_name="dev", region_name="us-east-1")
        self._dynamo = dev_session.resource("dynamodb")
        self._reserved_cidrs: list = []
        self._min_cidrs_count: int = 2
        self._reserved_octets: list = []
        self._available_app_cidr: str = ""
        self._available_data_cidr: str = ""

    def execute(self) -> Dict[str, str]:
        """
        Return two available CIDRs for the new environment
        """
        try:
            self.__prepare_reserved_cidrs_of_all_existing_envs()
            logger.info(f"Reserved CIDRs: {json.dumps(self._reserved_cidrs, indent=2)}")
            self.__prepare_reserved_octets()
            self.__prepare_available_cidrs()
            return {"vpc_app_cidr": str(self._available_app_cidr), "vpc_data_cidr": str(self._available_data_cidr)}
        except Exception as e:
            raise Exception(f"GetAvailableCIDRs Unable to return available CIDRs: {str(e)}")

    def __prepare_available_cidrs(self):
        for i in range(0, 99):
            if i in self._reserved_octets or i + 100 in self._reserved_octets:
                continue
            if not self._available_app_cidr and not self._available_data_cidr:
                self._available_app_cidr = "10.{}.0.0/16".format(i)
                self._available_data_cidr = "10.{}.0.0/16".format(i + 100)

    def __prepare_reserved_octets(self) -> None:
        for cidr in self._reserved_cidrs:
            self._reserved_octets.append(int(cidr.split(".")[1]))

    def __prepare_reserved_cidrs_of_all_existing_envs(self) -> None:
        try:
            table = self._dynamo.Table(self.dynamo_table)
            response = table.scan()
            data: List[Dict[str, str]] = response["Items"]

            for record in data:
                self.__process_cidr_block(cidr_key="vpc_app_cidr", record=record)
                self.__process_cidr_block(cidr_key="vpc_data_cidr", record=record)

            if len(self._reserved_cidrs) < self._min_cidrs_count:
                raise Exception(f"GetAvailableCIDRs Unable to fetch minimum number of CIDRs from dynamo db!")
        except Exception as e:
            raise Exception(f"GetAvailableCIDRs Unable to fetch CIDRs from dynamo db: {str(e)}")

    def __process_cidr_block(self, cidr_key: str, record: Dict[str, str]) -> None:
        if cidr_key in record and record[cidr_key]:
            if record[cidr_key] not in self._reserved_cidrs:
                self._reserved_cidrs.append(record[cidr_key])


def main():
    """
    Main method --> Starting from here
    @return: success/fail
    """
    try:
        logging.basicConfig(level=logging.INFO)
        result = GetAvailableCIDRs().execute()
        logger.info(f"Available CIDRs: {json.dumps(result, indent=2)}")
    except Exception as ex:
        logger.error(f"Main execution failed with {str(ex)}")


if __name__ == "__main__":
    main()
