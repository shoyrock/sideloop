"""Device protocol boundary checks without a physical phone."""
import contextlib
import unittest
from unittest.mock import Mock, patch
from sideloop import lockdown, renewal


class DeviceServicesTests(unittest.TestCase):
    def service(self, *replies):
        service = Mock()
        service.receive.side_effect = replies
        return service, contextlib.nullcontext(service)

    def test_browse_waits_for_complete_and_keeps_all_pages(self):
        service, context = self.service(
            {'Status': 'BrowsingApplications', 'CurrentList': [{'CFBundleIdentifier': 'a'}]},
            {'Status': 'BrowsingApplications', 'CurrentList': [{'CFBundleIdentifier': 'b'}]},
            {'Status': 'Complete'})
        phone = renewal.Phone('test')
        with patch.object(phone, 'service', return_value=context):
            self.assertEqual(set(phone.applications()), {'a', 'b'})
        service.send.assert_called_once_with({'Command':'Browse', 'ClientOptions':{'ApplicationType':'User'}})

    def test_browse_failure_is_not_an_empty_installed_app_list(self):
        _, context = self.service({'Error':'DeviceLocked'})
        phone = renewal.Phone('test')
        with patch.object(phone, 'service', return_value=context), self.assertRaises(ConnectionError):
            phone.applications()

    def test_profile_install_requires_success_acknowledgement(self):
        phone = renewal.Phone('test')
        for response in ({'Status': -1}, {}, {'Status': '0'}):
            service, context = self.service(response)
            with patch.object(phone, 'service', return_value=context), self.assertRaises(ConnectionError):
                phone.install(b'profile')
            service.send.assert_called_once_with({'MessageType':'Install','ProfileType':'Provisioning','Profile':b'profile'})

    def test_usb_is_preferred_when_same_device_also_appears_on_wifi(self):
        socket = Mock(); socket.__enter__ = Mock(return_value=socket); socket.__exit__ = Mock(return_value=False)
        devices = [{'DeviceID':1,'Properties':{'SerialNumber':'abc','ConnectionType':'Network'}},
                   {'DeviceID':2,'Properties':{'SerialNumber':'ABC','ConnectionType':'USB'}}]
        with patch.object(lockdown,'_mux_connect',return_value=socket), patch.object(lockdown,'_mux_request',return_value={'DeviceList':devices}):
            self.assertEqual(lockdown._device_id('abc','mux'),2)

    def test_failed_session_closes_its_connection(self):
        socket = Mock()
        with patch.object(lockdown,'_pair_record',return_value={'HostID':'host','SystemBUID':'system'}), \
             patch.object(lockdown,'_device_id',return_value=1), patch.object(lockdown,'_mux_connect',return_value=socket), \
             patch.object(lockdown,'_mux_request',return_value={'Number':0}), \
             patch.object(lockdown.Lockdown,'_call',return_value={'Error':'DeviceLocked'}):
            with self.assertRaises(PermissionError): lockdown.Lockdown('test','mux')
        socket.close.assert_called_once()


if __name__ == '__main__': unittest.main()
