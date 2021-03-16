import logging
from django.shortcuts import render

logger = logging.getLogger(__name__)

'''
    Initial page just to init the demo
'''
def index(request):
    return render(request, 'index.html')