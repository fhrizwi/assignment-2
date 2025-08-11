from pyramid.config import Configurator
from pyramid.response import Response

def main(global_config, **settings):
    config = Configurator(settings=settings)
    config.add_route('signup', '/signup')
    config.add_route('login', '/login')
    config.add_route('deposit', '/deposit')
    config.add_route('withdraw', '/withdraw')
    config.add_route('balance', '/balance')
    config.scan()
    return config.make_wsgi_app()
