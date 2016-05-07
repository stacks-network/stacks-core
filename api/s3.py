import requests
import traceback
import StringIO
import boto

from . import app


def s3_upload_file(bucket_name, value, key, content_type='text/plain',
                   public=False, headers=None, expires_in=600):
    try:
        conn = boto.connect_s3(app.config['AWS_ACCESS_KEY_ID'],
                               app.config['AWS_SECRET_ACCESS_KEY'])
        bucket = conn.get_bucket(bucket_name)
        k = boto.s3.key.Key(bucket)
        k.key = key
        fp = StringIO.StringIO(value)
        if not headers:
            headers = {'content-type': content_type}
        k.set_contents_from_file(fp, headers=headers)
        if public:
            k.make_public()
    except Exception, e:
        traceback.print_exc()
        return None

    url = "https://" + bucket_name + ".s3.amazonaws.com/" + key
    return url


def s3_upload_from_url(url, bucket_name, key):
    try:
        conn = boto.connect_s3(app.config['AWS_ACCESS_KEY_ID'],
                               app.config['AWS_SECRET_ACCESS_KEY'])
        bucket = conn.get_bucket(bucket_name)
        k = boto.s3.key.Key(bucket)
        k.key = key
        r = requests.get(url)
        content_type = r.headers['Content-Type']
        fp = StringIO.StringIO(r.content)
        k.set_contents_from_file(fp, headers={'content-type': content_type})
        k.make_public()
    except Exception, e:
        traceback.print_exc()
        return None

    url = "https://s3.amazonaws.com/" + bucket_name + "/" + key
    return url


def get_file_url_from_s3(bucket_name, key, expires_in=600):
    try:
        conn = boto.connect_s3(app.config['AWS_ACCESS_KEY_ID'],
                               app.config['AWS_SECRET_ACCESS_KEY'])
        url = conn.generate_url(expires_in, 'GET', bucket_name, key)
    except Exception, e:
        return None
    return url


def delete_file_from_s3(bucket_name, key):
    try:
        conn = boto.connect_s3(app.config['AWS_ACCESS_KEY_ID'],
                               app.config['AWS_SECRET_ACCESS_KEY'])
        bucket = conn.get_bucket(bucket_name)
        bucket.delete_key(key)
    except Exception, e:
        return False
    return True
