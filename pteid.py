# coding: utf-8

from os import listdir
from time import sleep
import PyKCS11
from PyKCS11 import PyKCS11Error, PyKCS11Lib, Mechanism

from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext,\
    X509StoreFlags, X509StoreContextError

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.exceptions import *

import logging

'''
    This class has all operations that can be executed on a provided Portuguese Citizen Card connected to the
    computer, based on the slot they are occupying.
'''
class PortugueseCitizenCard:

    def __init__(self):

        logging.info('Entering CC interface')

        self.cert=None

        rootCerts, trustedCerts, crlList = self._loadPkiCertsAndCrls()
    
        self.ccStoreContext = self._ccStoreContext(rootCerts, trustedCerts, crlList)
        logging.info('Store Context description completed')

        self.lib = 'libpteidpkcs11.so'
        self.cipherMechanism = Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, '')
        self.sessions = self.__initPyKCS11__()
        self.fullnames = self.getSmartcardsNames()

    '''
        Convert all the data retrived from the cert and crl files encoded in PEM or ASN1 format
    '''
    def _loadPkiCertsAndCrls(self):
        rootCerts = ()
        trustedCerts = ()
        crlList = ()

        basename = ['certLists/', 'crlLists/']

        for filename in listdir(basename[0]):
            try:
                cert_info = open(basename[0] + filename, 'rb').read()
            except IOError:
                logging.error( 'IO Exception while reading file : {:s} {:s}'.format(basename[0], filename))
                exit(10)
            else:
                if '.cer' in filename:
                    try:
                        if '0012' in filename or '0013' in filename:
                            certAuth = load_certificate(FILETYPE_PEM, cert_info)
                        else:
                            certAuth = load_certificate(FILETYPE_ASN1, cert_info)
                    except Error:
                        logging.error( 'Exception while loading certificate from file : {:s} {:s}'.format(
                            basename[0], filename))
                        exit(10)
                    else:
                        trustedCerts = trustedCerts + (certAuth,)
                elif '.crt' in filename:
                    try:
                        if 'ca_ecc' in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        elif '-self' in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        else:
                            root = load_certificate(FILETYPE_ASN1, cert_info)
                    except Error:
                        logging.error('Exception while loading certificate from file : {:s} {:s}'.format(
                            basename[0], filename))
                        exit(10)
                    else:
                        rootCerts = rootCerts + (root,)

        logging.info('Loaded Root certificates : {:d} out of {:d} '.format(len(rootCerts),
                                                                                      len(listdir(basename[0]))))
        logging.info('Loaded Authentication certificates: {:d} out of {:d} '.format(len(trustedCerts), len(
            listdir(basename[0]))))

        for filename in listdir(basename[1]):
            try:
                crl_info = open(basename[1] + '/' + filename, 'rb').read()
            except IOError:
                logging.error('IO Exception while reading file : {:s} {:s}'.format(basename[0], filename))
            else:
                if '.crl' in filename:
                    crls = load_crl(FILETYPE_ASN1, crl_info)
            crlList = crlList + (crls,)
        logging.info('Certificate revocation lists loaded: {:d} out of {:d} '.format(len(crlList), len(
            listdir(basename[1]))))

        return rootCerts, trustedCerts, crlList

    '''
        Creates a X509StoreContext Description that can be used to validate a given Citizen Card
    '''
    def _ccStoreContext(self, rootCerts, trustedCerts, crlList):
        try:
            store = X509Store()

            i = 0
            for _rootCerts in rootCerts:
                store.add_cert(_rootCerts)
                i += 1

            logging.info('Root Certificates Added to the X509 Store Context description : {:d}'.format(i))

            i = 0
            for _trustedCerts in trustedCerts:
                store.add_cert(_trustedCerts)
                i += 1

            logging.info('Trusted Authentication Certificates Added to the X509 Store Context description : {:d}'.format(i))

            i = 0
            for _crlList in crlList:
                store.add_crl(_crlList)
                i += 1

            logging.info('Certificates Revocation Lists Added to the X509 Store Context description : {:d}'.format(i))

            store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)
        except X509StoreContext:
            logging.error('Store Context description failed')
            return None
        else:
            return store

    '''
        Initialize the use of the the PyKCS11 module
    '''
    def __initPyKCS11__(self):
        AUTH_CERT_LABEL = 'CITIZEN AUTHENTICATION CERTIFICATE'
        AUTH_KEY_LABEL = 'CITIZEN AUTHENTICATION KEY'

        SIGN_CERT_LABEL = 'CITIZEN SIGNATURE CERTIFICATE'
        SIGN_KEY_LABEL = 'CITIZEN SIGNATURE KEY'

        logging.info( 'Entering PyKCS11 init ')
        try:
            pkcs11 = PyKCS11Lib()
            pkcs11.load(self.lib)
        except PyKCS11Error:
            logging.error('PortugueseCitizenCard: We could not load the PyKCS11 lib')
            Exception('We could not load the lib')
            exit(10)
        except KeyboardInterrupt:
            logging.info('PortugueseCitizenCard: Exiting Module by Keyboard Interruption')
            exit(0)
        else:
            try:
                # listing all card slots
                self.slots = pkcs11.getSlotList(tokenPresent=True)
                logging.info('The program found ' + str(len(self.slots)) + ' slots')

                if len(self.slots) < 1:
                    exit(-1)

                return [pkcs11.openSession(self.slots[x]) for x in range(0, len(self.slots))]

            except KeyboardInterrupt:
                logging.info('Exiting Module by Keyboard Interruption')
                exit(0)
            except PyKCS11Error:
                logging.error('We could not execute the method openSession for the given smartcard')
                exit(10)
            except:
                logging.error('Exiting Module because no CC was found')
                exit(11)

    '''
        This method gets the Name of the owner of the CC by fetching it from the CKA_SUBJECT field on the present CC session
    '''
    def PTEID_GetID(self, sessionIdx):
        AUTH_CERT_LABEL = 'CITIZEN AUTHENTICATION CERTIFICATE'

        logging.info('Entering PTEID_GetID with PyKCSS session id: {:2d}'.format(sessionIdx))

        try:
            info = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL),
                                                                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]))
        except PyKCS11Error:
            logging.error('The the smartcard with the id: {:3d} unexpectedly closed the session'.format(sessionIdx))
            return None
        else:
            try:
                infos1 = ''.join(chr(c) for c in [c.to_dict()['CKA_SUBJECT'] for c in info][0])
            except (IndexError, TypeError):
                logging.error('Certificate \'{:15s}\' not found in PyKCSS session with the id :{:2d}'.format(AUTH_CERT_LABEL))
                return None
            else:
                names = infos1.split('BI')[1].split('\x0c')
                return ' '.join(names[i] for i in range(1, len(names)))
    '''
        Gets the Name of the owner of the CC by fetching it from the CKA_SUBJECT field on the present CC session
    '''
    def PTEID_GetBI(self, sessionIdx):
        AUTH_CERT_LABEL = 'CITIZEN AUTHENTICATION CERTIFICATE'

        logging.info('Entering PTEID_GetID with PyKCSS session id: {:2d}'.format(sessionIdx))

        try:
            info = self.sessions[sessionIdx].findObjects(template=([(PyKCS11.CKA_LABEL, AUTH_CERT_LABEL),
                                                                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]))
        except PyKCS11Error:
            logging.error('The the smartcard with the id: {:3d} unexpectedly closed the session'.format(sessionIdx))
            return None
        else:
            try:
                infos1 = ''.join(chr(c) for c in [c.to_dict()['CKA_SUBJECT'] for c in info][0])
            except (IndexError, TypeError):
                logging.error('Certificate \'{:15s}\' not found in PyKCSS session with the id :{:2d}'.format(AUTH_CERT_LABEL))
                return None
            else:
                bi = infos1.split('BI')[1][:8]
                return bi

    '''
        Return CC serial number
    '''
    def certGetSerial(self):
        if not self.cert is None:
            return self.cert.serial_number
        return None

    '''
        Retreive the CITIZEN AUTHENTICATION CERTIFICATE from a connected CC smartcard
    '''
    def PTEID_GetCertificate(self, slot):
        AUTH_CERT_LABEL = 'CITIZEN AUTHENTICATION CERTIFICATE'

        logging.info('Entering PTEID_GetCertificate with PyKCSS session id :{:2d}'.format(slot))

        try:
            info = self.sessions[slot].findObjects(
                template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_LABEL, AUTH_CERT_LABEL)]))
        except PyKCS11Error:
            logging.error('The the smartcard in the slot with the id: {:3d} unexpectedly closed the session'.format(slot))
            exit(12)
        else:
            try:

                der = bytes([c.to_dict()['CKA_VALUE'] for c in info][0])

            except (IndexError, TypeError):
                logging.error('Certificate \'{:15s}\' not found in PyKCSS session with the id :{:2d}'.format(AUTH_CERT_LABEL))
                return None
            else:
                # converting DER format to x509 certificate
                try:
                    cert = x509.load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)
                except:
                    logging.error('Certificate for smartcard in the slot:{:2d} was not loaded: \n'.format(slot))
                    return None
                else:
                    logging.info('Certificate for smartcard in the slot:{:2d} loaded:\n {:s}'.format(slot, cert.decode('utf-8')))
                    self.cert = x509.load_pem_x509_certificate(cert, default_backend())
                    return cert

    '''
        Gets all names of the owners of the Portuguese Citizen Cards attached to the Computer
    '''
    def getSmartcardsNames(self):
        try:
            fullnames = [self.PTEID_GetID(i) for i in self.slots]
        except:
            logging.error('The service was unable to fetch all smartcards data')
            return None
        else:
            return fullnames

    '''
        This method can be used to login a User into a PyKCS11 session of the Citizen Card
    '''
    def login(self, slot):
        session = self.sessions[slot]
        name = self.fullnames[slot]

    '''
        Signs a string using the Private Key of the Portuguese Citizen Card
    '''
    def sign_data(self, slot, data):
        label = 'CITIZEN AUTHENTICATION KEY'

        session = self.sessions[slot]
        cipherMechnism = Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, '')

        if isinstance(data, str):
            try:
                privateKey = self.sessions[slot].findObjects(template=([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')]))[0]

                signedBytelist = session.sign(privateKey, data.encode(), cipherMechnism)
                logging.info('The smartcard with the id: {:3d}\n Signed this Data: {:15s} \n Signature : {}'.format(slot, data, bytes(signedBytelist)))
            except PyKCS11Error:
                logging.error('The smartcard with the id: {:3d} unexpectedly closed the session while trying to sign data'.format(slot))
            except IndexError:
                logging.error('The smartcard with the id: {:3d} unexpectedly closed the session'.format(slot))
            else:
                return bytes(signedBytelist)
        return None

    '''
        Verify the signature of a document/string signed using a certificate that was provided before.
        The certificate must pass the test of trust by verifying the Chain of Trust of the Portuguese Citizen Card
    '''
    def verifySignature(self, cert, data, signature):
        cert = x509.load_pem_x509_certificate(cert, default_backend())
        pubk = cert.public_key()
        padding = _aspaadding.PKCS1v15()

        if not isinstance(pubk, rsa.RSAPublicKey):
            logging.error('The provided certificate does not have a RSA public Key')
            return False
        try:
            state = pubk.verify(
                signature,
                bytes(data.encode()),
                padding,
                hashes.SHA256(),
            )

        except InvalidSignature as strerror:
            logging.error('Invalid Signature %s'.format(strerror.__doc__))
            return False
        except TypeError:
            logging.error('Invalid Signature %s'.format(TypeError.__doc__))
            return False
        else:
            #logging.info('The smartcard with the id: {:3d} signed data. Signature :\n{} \n Status: Signature'
            #'Verified'.format(slot,signature))
            return True

    '''
        This method can be used to logout a User
    '''
    def logout(self, slot):
        try:
            session = self.sessions[slot]
            session.logout()
            session.closeSession()
        except PyKCS11Error as strerror:
            session.closeSession()
            logging.debug('No open session found for slot with the id :{:2d} \nInfo : \n{:15s}'.format(slot, strerror.__doc__))

    '''
        Obtain the name of the user from the cert
    '''

    def GetNameFromCERT(self,cert):
        if isinstance(cert,str):
            cert = cert.encode()
        cert=x509.load_pem_x509_certificate(cert, default_backend())
        nameattribute=cert.subject
        relativedistinguishedname = [
            x509.RelativeDistinguishedName([x]) for x in nameattribute
        ][-1]
        name=relativedistinguishedname._attributes[0].value
        return name
'''
if __name__ == '__main__':
    try:
        pteid = PortugueseCitizenCard()
        fullnames = pteid.getSmartcardsNames()

        slot = -1
        if len(pteid.sessions) > 0:
            temp = ''.join('Slot{:3d}-> Fullname: {:10s}\n'.format(i, fullnames[i]) for i in range(0, len(fullnames)))

            while slot < 0 or slot > len(pteid.sessions):
                slot = input('Available Slots: \n{:40s} \n\nWhich Slot do you wish to use? '.format(temp))
                if slot.isdigit():
                    slot = int(slot)
                else:
                    slot = -1
        for i in range(0, len(pteid.sessions)):
            if slot != i:
                pteid.sessions[i].closeSession()
        print(pteid.PTEID_GetBI(slot))


        st1r = pteid.PTEID_GetCertificate(slot)

        print('The certificate is from : {}'.format(pteid.GetNameFromCERT(st1r)))

        pteid.login(slot)

        datatobeSigned = 'Data sign'
        signedData = pteid.sign_data(slot, datatobeSigned)

        print(datatobeSigned + '\n')

        if (pteid.verifySignature(pteid.PTEID_GetCertificate(slot), datatobeSigned, signedData)):
            print('Verified')

    except KeyboardInterrupt:
        pteid.logout(slot)
        pteid.sessions[slot].closeSession()

    else:
        pteid.logout(slot)
        pteid.sessions[slot].closeSession()
'''