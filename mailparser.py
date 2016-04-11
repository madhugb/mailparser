#!/bin/env python
#
# MailParser
#
# Inspired by Alain Spineux <alain.spineux@gmail.com>
#
# Modified by Madhu G B <me@madhugb.com>

import sys
import os
import re
import StringIO
import email
import mimetypes
import base64
import traceback
from email.parser import HeaderParser
from email.header import make_header
from email.header import decode_header

class MailParser(object):

	invalid_chars_in_filename = '<>:"/\\|?*\%\''+ \
								reduce(lambda x,y:x+chr(y), range(32), '')
	invalid_windows_name = 'CON PRN AUX NUL COM1 COM2 COM3 COM4 COM5 COM6 COM7 COM8 COM9 LPT1 LPT2 LPT3 LPT4 LPT5 LPT6 LPT7 LPT8 LPT9'.split()

	# email address REGEX matching the RFC 2822 spec from perlfaq9
	#    my $atom       = qr{[a-zA-Z0-9_!#\$\%&'*+/=?\^`{}~|\-]+};
	#    my $dot_atom   = qr{$atom(?:\.$atom)*};
	#    my $quoted     = qr{"(?:\\[^\r\n]|[^\\"])*"};
	#    my $local      = qr{(?:$dot_atom|$quoted)};
	#    my $domain_lit = qr{\[(?:\\\S|[\x21-\x5a\x5e-\x7e])*\]};
	#    my $domain     = qr{(?:$dot_atom|$domain_lit)};
	#    my $addr_spec  = qr{$local\@$domain};
	#
	# Python's translation

	atom_rfc2822 = r"[a-zA-Z0-9_!#\$\%&'*+/=?\^`{}~|\-]+"

	# without '!' and '%'
	atom_posfix_restricted = r"[a-zA-Z0-9_#\$&'*+/=?\^`{}~|\-]+"

	atom = atom_rfc2822

	dot_atom = atom  +  r"(?:\."  +  atom  +  ")*"

	quoted = r'"(?:\\[^\r\n]|[^\\"])*"'

	local = "(?:"  +  dot_atom  +  "|"  +  quoted  +  ")"

	domain_lit = r"\[(?:\\\S|[\x21-\x5a\x5e-\x7e])*\]"

	domain = "(?:"  +  dot_atom  +  "|"  +  domain_lit  +  ")"

	addr_spec = local  +  "\@"  +  domain

	email_address_re = re.compile('^'+addr_spec+'$')

	headers = dict()

	def set_headers(self, part):
		parser = HeaderParser()
		# get all headers and store them in dict with lower key
		headers = { key.lower().strip('.') : unicode(make_header(decode_header(value))) for key, value in parser.parsestr(part).items()}
		self.headers = headers
		return

	def decode_header(self, header_text, default="ascii"):
		"""Decode header_text if needed"""
		try:
			head = email.Header.decode_header(header_text)
		except email.Errors.HeaderParseError:
			return header_text.encode('ascii', 'replace').decode('ascii')
		else:
			for i, (text, charset) in enumerate(head):
				try:
					head[i]=unicode(text, charset or default,
											errors='replace')
				except LookupError:
					# if the charset is unknown, force default
					head[i]=unicode(text, default, errors='replace')
			return u"".join(head)

	def getmailaddresses(self, name):
		"""retrieve addresses from header, 'name' supposed to be from, to,  ...
		"""
		emails = list()
		if name in self.headers:
			for e in email.utils.getaddresses([self.headers[name]]):
				emails.append({
					'id': e[1],
					'name': e[0]})
		return emails

	def get_filename(self, part):
		"""Many mail user agents send attachments with the filename in
		the 'name' parameter of the 'content-type' header instead
		of in the 'filename' parameter of the 'content-disposition' header.
		"""
		filename=part.get_param('filename', None, 'content-disposition')
		if not filename:
			filename=part.get_param('name', None) # default is 'content-type'
		if not filename:
			filename=part.get_param('alt', None)

		if filename:
			# RFC 2231 must be used to encode parameters inside MIME header
			filename=email.Utils.collapse_rfc2231_value(filename).strip()

		if filename and isinstance(filename, str):
			# But a lot of MUA erroneously use RFC 2047 instead of RFC 2231
			# in fact anybody miss use RFC2047 here !!!
			filename = self.decode_header(filename)

		return filename


	def get_message_id(self):
		try:
			return self.headers['message-id']
		except:
			return None

	def get_date(self):
		mail_date = None
		if 'date' in self.headers:
			mail_date = self.headers['date']
		return mail_date

	def _search_message_bodies(self, bodies, part):
		"""recursive search of the multiple version of the 'message' inside
		the the message structure of the email, used by search_message_bodies()
		"""

		type = part.get_content_type()
		if type.startswith('multipart/'):
			# explore only True 'multipart/*'
			# because 'messages/rfc822' are also python 'multipart'
			if type == 'multipart/related':
				# the first part or the one pointed by start
				start = part.get_param('start', None)
				related_type = part.get_param('type', None)
				for i, subpart in enumerate(part.get_payload()):
					if (not start and i==0) or \
							(start and start==subpart.get('Content-Id')):
						self._search_message_bodies(bodies, subpart)
						return
			elif type=='multipart/alternative':
				# all parts are candidates and latest is best
				for subpart in part.get_payload():
					self._search_message_bodies(bodies, subpart)
			elif type in ('multipart/report',  'multipart/signed'):
				# only the first part is candidate
				try:
					subpart=part.get_payload()[0]
				except IndexError:
					return
				else:
					self._search_message_bodies(bodies, subpart)
					return

			elif type=='multipart/signed':
				# cannot handle this
				return

			else:
				# unknown types must be handled as 'multipart/mixed'
				# This is the peace of code could probably be improved,
				# I use a heuristic :
				# - if not already found,
				#      use first valid non 'attachment' parts found
				for subpart in part.get_payload():
					tmp_bodies=dict()
					self._search_message_bodies(tmp_bodies, subpart)
					for k, v in tmp_bodies.iteritems():
						if not subpart.get_param('attachment',
									None, 'content-disposition')=='':
							# if not an attachment, initiate value
							# if not already found
							bodies.setdefault(k, v)
				return
		else:
			bodies[part.get_content_type().lower()]=part
			return
		return

	def search_message_bodies(self, mail):
		"""search message content into a mail"""
		bodies = dict()
		self._search_message_bodies(bodies, mail)
		return bodies

	def get_mail_contents(self, msg):
		"""split an email in a list of attachments"""

		attachments = []

		# retrieve messages of the email
		bodies = self.search_message_bodies(msg)

		# reverse bodies dict
		parts = dict((v,k) for k, v in bodies.iteritems())

		# organize the stack to handle deep first search
		stack=[ msg, ]
		while stack:
			part = stack.pop(0)
			content_type = part.get_content_type()
			if content_type.startswith('message/'):

				# ('message/delivery-status',
				#   'message/rfc822',
				#   'message/disposition-notification'):
				# I don't want to explore the tree deeper here
				# and just save source using msg.as_string()
				# but I don't use msg.as_string()
				# because I want to use mangle_from_=False

				fp = StringIO.StringIO()
				g = Generator(fp, mangle_from_=False)
				g.flatten(part, unixfrom=False)
				payload=fp.getvalue()
				filename='mail.eml'
				attachments.append(Attachment(part,
					filename = filename,
					type = content_type,
					payload = payload,
					charset = part.get_param('charset'),
					description = part.get('Content-Description')))

			elif part.is_multipart():
				# insert new parts at the beginning
				# of the stack (deep first search)
				stack[:0]=part.get_payload()
			else:
				payload = part.get_payload(decode=True)
				charset = part.get_param('charset')
				filename = self.get_filename(part)
				disposition = None

				if part.get_param('inline', None,
									'content-disposition')=='':
					disposition = 'inline'

				elif part.get_param('attachment', None,
									'content-disposition') =='':
					disposition = 'attachment'

				attachments.append(Attachment(part,
					filename = filename,
					type = content_type,
					payload = payload,
					charset = charset,
					content_id = part.get('Content-Id'),
					description = part.get('Content-Description'),
					disposition = disposition,
					is_body = parts.get(part)))

		return attachments

	def decode_text(self, payload, charset, default_charset):

		if charset:
			try:
				return payload.decode(charset), charset
			except UnicodeError:
				pass

		if default_charset and default_charset != 'auto':
			try:
				return payload.decode(default_charset), default_charset
			except UnicodeError:
				pass

		for chset in [ 'ascii', 'utf-8', 'utf-16', 'windows-1252', 'cp850' ]:
			try:
				return payload.decode(chset), chset
			except UnicodeError:
				pass

		return payload, None

	def get_people(self):
		people = {'from': list(), 'to': list(), 'cc': list(), 'bcc': list()}
		return { ptype: self.getmailaddresses(ptype) \
					for ptype, value in people.items()}

	def parse(self, raw):
		message = {}
		msg = email.message_from_string(raw)
		try:
			self.set_headers(part=raw)

			people = self.get_people()
			sub = msg.get('subject', '').replace('\n','')
			message['subject'] = self.decode_header(sub)
			message['date'] = self.get_date()
			message['thread_info'] = {
				"references" : self.headers['references'] if "references" in self.headers else "",
				"in-reply-to": self.headers['in-reply-to'] if "in-reply-to" in self.headers else ""
			}
			message['headers'] = self.headers
			message['from'] = people['from']
			message['message_id'] = self.get_message_id()
			message['to'] = people['to']
			message['cc'] = people['cc']
			message['bcc'] = people['bcc']
			message['attachments'] = list()
			body = {'plain':None,'html':None}
			for content in self.get_mail_contents(msg):
				if content.is_body == 'text/plain':
					payload, used_charset = self.decode_text(content.payload,
											content.charset, 'auto')
					body['plain'] = {
						'data': payload,
						'charset': used_charset,
						'size': 0 if (content.payload == None) else len(content.payload)
					}
				if content.is_body == 'text/html':
					payload, used_charset = self.decode_text(content.payload,
											content.charset, 'auto')
					body['html'] = {
						'data': payload,
						'charset': used_charset,
						'size': 0 if (content.payload == None) else len(content.payload)
					}

				if content.is_body == None:
					message['attachments'].append({
						'id': content.content_id,
						'cid': content.content_id,
						'filename': content.filename,
						'content': content.payload,
						'type': content.type,
						'disposition': content.disposition})
			message['body'] = ""
			message['size'] = 0
			if body['html']:
				message['body'] = body['html']['data']
				message['size'] = body['html']['size']
			elif body['plain']:
				message['body'] = "<div>%s</div>" % body['plain']['data']
				message['size'] = body['plain']['size']
		except:
			exc_type, exc_value, exc_traceback = sys.exc_info()
			traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
			traceback.print_exception(exc_type, exc_value, exc_traceback, limit=2, file=sys.stdout)

		return message

class Attachment:

	def __init__(self,
			part,
			filename=None,
			type=None,
			payload=None,
			charset=None,
			content_id=None,
			description=None,
			disposition=None,
			sanitized_filename=None,
			is_body=None):

		self.part = part          # original python part
		self.filename = filename  # filename in unicode (if any)
		self.type = type          # the mime-type
		self.payload = payload    # the MIME decoded content
		self.charset = charset    # the charset (if any)
		self.description = description    # if any
		self.disposition = disposition    # 'inline', 'attachment' or None

		# cleanup your filename here (TODO)
		self.sanitized_filename = sanitized_filename

		# usually in (None, 'text/plain' or 'text/html')
		self.is_body = is_body

		# if any content_id
		self.content_id = content_id

		if self.content_id:
			# strip '<>' to ease searche and replace in "root" content (TODO)
			if self.content_id.startswith('<') and \
					self.content_id.endswith('>'):
				self.content_id=self.content_id[1:-1]