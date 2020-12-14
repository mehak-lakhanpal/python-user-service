from flask import make_response, request, json, jsonify, current_app
from flask_login import current_user, login_user, logout_user, login_required
from marshmallow import ValidationError
from passlib.hash import sha256_crypt
from repository.models import db, User, UserSchemaCreateRequest,UserSchemaUpdateRequest, UserSchemaResponse
from shared import constants
from sqlalchemy import or_

from . import user_api_blueprint


@user_api_blueprint.route("/api/user/docs.json", methods=['GET'])
def swagger_api_docs_yml():
    with open('./static/swagger.json') as fd:
        json_data = json.load(fd)

    return jsonify(json_data)


@user_api_blueprint.route('/api/users', methods=['GET'])
@login_required
def get_users():
    current_app.logger.info(constants.USER_LOGGER, current_user.username)
    user_schemas = UserSchemaResponse(many=True)
    users = User.query.all()
    current_app.logger.info(constants.USERS_LOGGER, users)
    return jsonify(user_schemas.dump(users))


@user_api_blueprint.route('/api/user/login', methods=['POST'])
def post_login():

    username = request.json['username']
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            if sha256_crypt.verify(str(request.json['password']), user.password):
                user.encode_api_key()
                db.session.commit()
                login_user(user)
                current_app.logger.info(constants.USER_LOGGED_SUCCESS, user.username)
                return make_response(jsonify({constants.MESSAGE: 'Logged in', 'api_key': user.api_key}))

        current_app.logger.info(constants.USER_LOGGED_FAILED, username)
        return make_response(jsonify({constants.MESSAGE: 'Not logged in'}), 401)
    except Exception as ex:
        current_app.logger.error(constants.EXCEPTION_LOGGER, ex)
        return jsonify({constants.ERRORS: str(ex)}), 500


@user_api_blueprint.route('/api/user/<username>/exists', methods=['GET'])
@login_required
def get_username(username):

    user = User.query.filter_by(username=username).first()
    if user is not None:
        current_app.logger.info(constants.USER_EXIST_LOGGER, username)
        response = jsonify({constants.EXISTS: True})
    else:
        current_app.logger.info(constants.USER_NOT_EXIST_LOGGER, username)
        response = jsonify({constants.EXISTS: False})

    return response


@user_api_blueprint.route('/api/user/logout', methods=['POST'])
@login_required
def post_logout():
    logout_user()
    current_app.logger.info(constants.USER_LOG_OUT_SUCCESS_LOGGER)
    return make_response(jsonify({constants.MESSAGE: constants.USER_LOG_OUT_SUCCESS}))


@user_api_blueprint.route('/api/user', methods=['GET'])
@login_required
def get_current_user():
    current_app.logger.info(constants.USER_SUCCESS_AUTHENTICATION,current_user.username)
    user_schema = UserSchemaResponse()
    return jsonify(user_schema.dump(current_user))

@user_api_blueprint.route('/api/user/<id>', methods=['GET'])
@login_required
def get_user_by_id(id):
    user = User.query.get(id)
    if user is not None:
        user_schema = UserSchemaResponse()
        current_app.logger.info(constants.USER_LOGGER,user)
        return jsonify(user_schema.dump(user))
    else:
        current_app.logger.info(constants.USER_NOT_FOUND_LOGGER,id)
        return make_response(jsonify({constants.MESSAGE: constants.USER_NOT_FOUND}), 404)

@user_api_blueprint.route('/api/user', methods=['POST'])
def post_register():

    # Validate and deserialize input
    try:
        user = UserSchemaCreateRequest().load(request.get_json())

        existing_user = User.query \
            .filter(or_(User.username == user.username,User.email == user.email)) \
            .one_or_none()

        if existing_user is None:
            user.password = sha256_crypt.hash((str(user.password)))
            user.authenticated = True
            user.active = True
            db.session.add(user)
            db.session.commit()
            current_app.logger.info('{} successfully added!'.format(user.username))
            response = jsonify({constants.MESSAGE: 'User added succesfully!','id':user.id}),201
        else:
            response =  jsonify({constants.MESSAGE: 'User with this email or username already exists'}), 409
        return response

    except ValidationError as err:
        current_app.logger.error(constants.VALIDATION_ERROR_LOGGER, err)
        return jsonify({constants.ERRORS: err.messages}), 400
    except Exception as ex:
        current_app.logger.error(constants.EXCEPTION_LOGGER, ex)
        return jsonify({constants.ERRORS: str(ex)}), 500


@user_api_blueprint.route('/api/user/<id>', methods=['PUT'])
@login_required
def update_user(id):
    try:
        existing_user = User.query.get(id)
        if existing_user is None:
            return make_response(jsonify({constants.MESSAGE: 'User with id: {} does\'nt exists'.format(id)}), 404)

        user = UserSchemaUpdateRequest().load(request.get_json())
        existing_user.first_name = user.first_name
        existing_user.last_name = user.last_name
        existing_user.email = user.email
        db.session.add(existing_user)
        db.session.commit()
        current_app.logger.info('{} successfully updated!'.format(existing_user.username))
        return make_response(jsonify({constants.MESSAGE: 'User updated succesfully!'}), 200)
    except ValidationError as err:
        current_app.logger.error(constants.VALIDATION_ERROR_LOGGER, err)
        return jsonify({constants.ERRORS: err.messages}), 400
    except Exception as ex:
        current_app.logger.error(constants.EXCEPTION_LOGGER, ex)
        return jsonify({constants.ERRORS: str(ex)}), 500



