from __future__ import absolute_import
from decimal import Decimal

from pprint import pprint
import requests

from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache

from thefuzz import fuzz

from .logger import LOGGER

import stdnum.us.tin
import stdnum.at.tin

import stdnum.us.ssn
import stdnum.at.vnr

from .unique_generators import random_string_generator


def validate_ssn(value):
    # Implement your validation logic here, potentially using a regular expression
    # Example:
    if not stdnum.at.vnr.is_valid(value) or not stdnum.us.ssn.is_valid(value):
        raise ValidationError(_("Invalid Social Security Number"))


def validate_tin(value):
    if not stdnum.at.tin.is_valid(value) or not stdnum.us.tin.is_valid(value):
        raise ValidationError(_("Invalid Tas Identification Number"))


def serializer_validate_phone(self, phone, serializers):
    if "+" in phone:
        return phone

    if "+" not in phone:
        raise serializers.ValidationError(_("Must start with +<country_code>. eg: +1"))

    if "@" in phone:
        raise serializers.ValidationError(_("Invalid Character in phone"))
    return phone


def image_validate_file_extension(value):
    LOGGER.info(value)
    valid_extensions: list[str] = [".jpeg", ".jpg", ".png", ".svg"]
    file_extension: str = value.name.split(".")[-1].lower()

    LOGGER.info(file_extension)

    if f".{file_extension}" in valid_extensions:
        return value
    raise ValidationError(_("File type is not supported. Supported file types are: .jpeg, .jpg, .png, .svg"))


def document_validate_file_extension(value):
    valid_extensions: list[str] = [".pdf", ".doc", ".txt"]
    file_extension: str = value.name.split(".")[-1].lower()

    if f".{file_extension}" in valid_extensions:
        return value
    raise ValidationError(_("File type is not supported. Supported file types are: .pdf, .doc, .docx"))


def video_validate_file_extension(value):
    valid_extensions: list[str] = [".mp4", ".mov", ".webm"]
    file_extension: str = value.name.split(".")[-1].lower()

    if f".{file_extension}" in valid_extensions:
        return value
    raise ValidationError(_("File type is not supported. Supported file types are: .mp4, .mov, .webm"))


def validate_credit_card(value, serializers):
    url = "https://check-credit-card.p.rapidapi.com/detect"

    payload = value
    headers = {
        "content-type": "application/json",
        "X-RapidAPI-Key": settings.RAPID_API_KEY,
        "X-RapidAPI-Host": "check-credit-card.p.rapidapi.com",
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        res = response.json()
        if not res["valid"]:
            raise serializers.ValidationError(_("Invalid credit card"))
        return value


def get_all_rates(code: str):
    url = "https://currency-converter241.p.rapidapi.com/convert"

    querystring = {"amount": "1", "from": "USD", "to": code.upper()}

    headers = {"X-RapidAPI-Key": settings.RAPIDAPI_KEY, "X-RapidAPI-Host": "currency-converter241.p.rapidapi.com"}

    response = requests.get(url, headers=headers, params=querystring)
    LOGGER.info(response.json())
    return response.json()


def get_ip_geolocation_info(ip):
    url = "https://ip-reputation-geoip-and-detect-vpn.p.rapidapi.com/"

    querystring = {"ip": str(ip)}

    headers = {
        "X-RapidAPI-Key": settings.RAPIDAPI_KEY,
        "X-RapidAPI-Host": "ip-reputation-geoip-and-detect-vpn.p.rapidapi.com",
    }

    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        LOGGER.info(response.json())
        return response.json()


def validate_bank_name(bank_name) -> bool:
    """
    Validates the bank name checking if there is a match above 70%

    Args:
        bank_name (str): Name of the bank typed in by the user

    Returns:
        bool: True or False if the user matched or not
    """
    # Retrieve the cached bank list
    cached_banks = cache.get("banks")

    # Check if the bank name exists in the cached list
    if cached_banks:
        for bank in cached_banks:
            similarity_ratio = fuzz.ratio(bank["name"].lower(), bank_name.lower())

            # Adjust the threshold as needed
            if similarity_ratio > 80:
                return True

    return False


def get_bank_id(bank_name) -> str | None:
    """
    Retrieves the cached paystack bank code

    Args:
        bankname (str): Name of the bank

    Returns:
        code (str): Paystack Bank Identifying Code
        or None
    """

    # Retrieve the cached bank list
    cached_banks = cache.get("banks")

    # Check if the bank name exists in the cached list
    if cached_banks:
        for bank in cached_banks:
            similarity_ratio = fuzz.ratio(bank["name"].lower(), bank_name.lower())

            # Adjust the threshold as needed
            if similarity_ratio > 80:
                return bank["code"]

    return None


def create_rider_transfer_recipient(bank, user):
    """
    Creates a paystack recipient object for the rider whenever they add a new bank account

    Args:
        bank (BankAccount): BankAccount Instance
        user (User): User instance
    """
    if user.is_rider:
        url = "https://api.paystack.co/transferrecipient"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        }
        data = {
            "type": "nuban",
            "name": bank.account_name,
            "account_number": bank.account_number,
            "bank_code": bank.bank_id,
            "currency": user.currency,
        }

        res = requests.request("POST", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            try:
                data = {
                    "id": res["data"]["id"],
                    "name": res["data"]["name"],
                    "recipient_code": res["data"]["recipient_code"],
                    "account_number": res["data"]["details"]["account_number"],
                    "bank_code": res["data"]["details"]["bank_code"],
                    "bank_name": res["data"]["details"]["bank_name"],
                }

                if not cache.has_key(user.email):
                    cache.set(user.email, data, timeout=None)
                LOGGER.info(f"Successfully added recipient")
            except Exception as e:
                LOGGER.error(e)
        else:
            LOGGER.error("Recipient Not Created")


def create_vendor_transfer_recipient(bank, vendor):
    """
    Creates a paystack recipient object for the vendors whenever they add a new bank account

    Args:
        bank (BankAccount): BankAccount Instance
        vendor (VendorShop): VendorShop instance
    """
    url = "https://api.paystack.co/transferrecipient"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }
    data = {
        "type": "nuban",
        "name": bank.account_name,
        "account_number": bank.account_number,
        "bank_code": bank.bank_id,
        "currency": "NGN",
    }

    res = requests.request("POST", url, headers=headers, data=data)
    res = res.json()
    pp = pprint.PrettyPrinter(indent=4)
    LOGGER.info(pp.pprint(res))

    if res["status"]:
        try:
            data = {
                "id": res["data"]["id"],
                "name": res["data"]["name"],
                "recipient_code": res["data"]["recipient_code"],
                "account_number": res["data"]["details"]["account_number"],
                "bank_code": res["data"]["details"]["bank_code"],
                "bank_name": res["data"]["details"]["bank_name"],
            }

            if not cache.has_key(vendor.slug):
                cache.set(vendor.slug, data, timeout=None)
            LOGGER.info(f"Successfully added recipient")
        except Exception as e:
            LOGGER.error(e)
    else:
        LOGGER.error("Recipient Not Created")


def get_recipient_data(key: str) -> dict:
    """
    Returns a dictionary of cached recipient information:

    "id": int,
    "name": str,
    "recipient_code": str,
    "account_number": str,
    "bank_code": str,
    "bank_name": str,

    """
    if cache.has_key(key):
        data: dict = cache.get(key)
        return data


def disable_otp():
    """
    Disables otp for transferring money to customers or vendors or riders
    """
    url = "https://api.paystack.co/transfer/disable_otp"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }

    res = requests.request("POST", url, headers=headers)
    res = res.json()
    pp = pprint.PrettyPrinter(indent=4)
    LOGGER.info(pp.pprint(res))

    if res["status"]:
        return res["message"]
    else:
        LOGGER.error("Disabling OTP has failed")
        return "Disabling OTP has failed"


def complete_disabling_otp(code):
    """
    Complete the otp disabling process by passing the sms code sent to a designated phone number
    """
    url = "https://api.paystack.co/transfer/disable_otp_finalize"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }
    data = {
        "otp": str(code),
    }

    res = requests.request("POST", url, headers=headers, data=data)
    res = res.json()
    pp = pprint.PrettyPrinter(indent=4)
    LOGGER.info(pp.pprint(res))

    if res["status"]:
        return res["message"]
    else:
        LOGGER.error("Disabling OTP has failed")
        return "Disabling OTP has failed"

def enable_otp():
    """
    Enable otp to ensure customers get otp before sending to them
    """
    url = "https://api.paystack.co/transfer/enable_otp"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }
    res = requests.request("POST", url, headers=headers)
    res = res.json()
    pp = pprint.PrettyPrinter(indent=4)
    LOGGER.info(pp.pprint(res))

    if res["status"]:
        return res["message"]
    else:
        LOGGER.error("nabling OTP has failed")
        return "Enabling OTP has failed"


def transfer_to_recipient(recipient_code: str, amount: int, reason: str):
    """
    Make transfers to recipient from their account balance.

    If the transfer status is 'otp', then open a new page to accept the otp code from the user
    then complete or finalize the transfer
    """
    reference = f"PO_{random_string_generator(size=36)}"
    url = "https://api.paystack.co/transfer"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }
    data = {
        "source":"balance",
        "reason": reason,
        "amount": amount,
        "recipient": recipient_code,
        "reference": reference,
    }
    res = requests.request("POST", url, headers=headers, data=data)
    res = res.json()
    pp = pprint.PrettyPrinter(indent=4)
    LOGGER.info(pp.pprint(res))

    if res["status"]:
        data = {
            "amount": amount,
            "currency": res['data']['currency'],
            "reason": res['data']['reason'],
            "status": res['data']['status'],
            "transaction_code": res['data']['transfer_code'],
            "transfer_reference": reference
        }
        return data
    else:
        LOGGER.error("Payout Unsuccessful")
        return None

def verify_transfer_status(reference: str):
    """
    Verify the transfer status
    """
    url = f"https://api.paystack.co/transfer/{reference}"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }
    res = requests.request("GET", url, headers=headers, data=data)
    res = res.json()
    pp = pprint.PrettyPrinter(indent=4)
    LOGGER.info(pp.pprint(res))

    if res["status"]:
        data = {
            "amount": res['data']['amount'],
            "currency": res['data']['currency'],
            "reason": res['data']['reason'],
            "status": res['data']['status'],
            "transaction_code": res['data']['transfer_code'],
            "transfer_reference": res['data']['reference']
        }
        return data
    else:
        LOGGER.error("Payout Unsuccessful")
        return None


def verify_transaction(reference: str):
    """
    Verify the transaction status
    """
    url = f"https://api.paystack.co/transfer/{reference}"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
    }
    res = requests.request("GET", url, headers=headers, data=data)
    res = res.json()
    pp = pprint.PrettyPrinter(indent=4)
    LOGGER.info(pp.pprint(res))

    if res["status"]:
        data = {
            "amount": res['data']['amount'],
            "currency": res['data']['currency'],
            "status": res['data']['status'],
            "transaction_code": res['data']['transfer_code'],
            "transfer_reference": res['data']['reference']
        }
        return data
    else:
        LOGGER.error("Verifying transaction Unsuccessful")
        return None

