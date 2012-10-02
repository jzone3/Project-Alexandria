from google.appengine.api import files
from google.appengine.api import urlfetch
import gdata.docs.service
import gdata.docs.data

result = urlfetch.fetch('https://dl.dropbox.com/s/q5gnoy8s0bwy3an/1-1%20notes.doc?dl=1')
headers = result.headers

client = gdata.docs.service.DocsService()
client.ClientLogin("jellyksong@gmail.com", 'accelerateacademy', 'test')

ms = gdata.MediaSource(file_handle=result.content, content_type=gdata.docs.service.SUPPORTED_FILETYPES['DOC'], content_length=int(headers['content-length']))

entry = client.Upload(ms, "test2")
