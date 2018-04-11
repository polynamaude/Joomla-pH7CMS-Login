<?php
/**
 * @package     Joomla pH7CMS Authentication Plugin
 * @subpackage  Authentication.pH7CMS Plugin Entry file
 *
 * @copyright   Copyright (C) 2018 Polyna-Maude R.-Summerside. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

require_once dirname(__FILE__).'/helper.php';

/**
 * php7CMS Authentication Plugin
 *
 * @package     Joomla pH7CMS Authentication Plugin
 * @subpackage  Authentication.pH7CMS
 * @since       0.1
 */

class PlgpH7CMSAuthentication extends \Joomla\CMS\Plugin\PluginHelper
{

	/*** Our salts. Never change these values, otherwise all passwords and other strings will be incorrect ***/
	const PREFIX_SALT = 'c好，你今Здраврыве ты ў паітаньне е54йте天rt&eh好嗎_dمرحبا أنت بخير ال好嗎attú^u5atá inniu4a,?478привіなたは大丈夫今日はтивпряьоהעלאai54ng_scси днесpt';
	const SUFFIX_SALT = '*éà12_you_è§§=≃ù%µµ££$);&,?µp{èàùf*sxdslut_waruआप नमस्क你好，你今ार ठΓει好嗎α σαςb안녕하세oi요 괜찮은 o नमस्कार ठीnjre;,?*-<καλά σήμεραीक आजсегодняm_54tjהעלאdgezsядкمرحبا';

	const HASH_LENGTH = 80;
	const COOKIE_HASH_LENGTH = 40;
	const PBKDF2_ITERATION = 10000;

	const PWD_ALGORITHM = PASSWORD_BCRYPT;
	const PWD_WORK_FACTOR = 12;

	const SHA512_ALGORITHM = 'sha512';
	const WHIRLPOOL_ALGORITHM = 'whirlpool';

	/*** Copied from pH7CMS source code
	 * @author         Pierre-Henry Soria <ph7software@gmail.com>
	 * @copyright      (c) 2012-2018, Pierre-Henry Soria. All Rights Reserved.
	 * @package        PH7 / Framework / Security
	 * @version        1.2
	 * ***/

 	/**
	 * Load the language file on instantiation. Note this is only available in Joomla 3.1 and higher.
	 * If you want to support 3.0 series you must override the constructor
	 *
	 * @var    boolean
	 * @since  3.1
	 */
	protected $autoloadLanguage = true;

	/**
	 * Connection to database
	 * @var JDatabaseDriver $db
	 */

	private $db;

	/**
	 * pH7CMS installation prefix default = ph7_
	 * @var string	$ph7prefix
	 */

	private $ph7prefix;

	private $dbResult;

	/**
	 *
	 * @var \Joomla\CMS\User\User	$pH7user
	 */

	private $pH7user;

	/**
	 *
	 * @var integer	$pH7userID
	 */

	private $pH7userID;

	/**
	 * We place the parameters into a registry object
	 * @var \Joomla\Registry\Registry $pluginParams
	 */

	private $pluginParams;

	/**
	 * Our response object
	 * @var \Joomla\CMS\Authentication\AuthenticationResponse	$response
	 */
	private $response;

	private function check_email ($username)
	{

	}

	private function getDbo()
	{
		/**
		 * We retrieve our plugin parameter using the long way around
		 * @var \Joomla\CMS\Plugin\CMSPlugin $plugin
		 */

		$plugin = \Joomla\CMS\Plugin\PluginHelper::getPlugin('authentication','ph7cms');


		$this->pluginParams = new \Joomla\Registry\Registry($plugin->params);

		if ($this->pluginParams->get('ph7dbsame','1') == '0')
		{
			/**
			 * pH7CMS Database options
			 * @var array $dbOptions
			 */
			$dbOptions = array();
			$dbOptions['driver'] = 'mysql';
			$dbOptions['host'] = $pluginParams->get('ph7dbhost','localhost');
			$dbOptions['user'] = $pluginParams->get('ph7user','dbuser');
			$dbOptions['password'] = $pluginParams->get('ph7pwd','dbpwd');
			$dbOptions['database'] = $pluginParams->get('ph7dbname','mydb');

			$this->db = \JDatabaseDriver::getInstance($dbOptions);
		}
		else
		{
			$this->db = \Joomla\CMS\Factory::getDbo();
		}

		$this->ph7prefix = $this->pluginParams->get('ph7prefix','ph7_');
	}

	private function checkPassword($credentials)
	{
		if ($this->db instanceof \JDatabaseDriver)
		{
			$this->getDbo();
		}

		/**
		 * Get a query referenced to pH7CMS members table and lookup username against provider credentials
		 * @var JDatabaseQuery $query
		 */
		$query = $this->db->getQuery(true)
		->select('username')
		->from($this->ph7prefix.'members')
		->where('username='.$db->quote($credentials['username']));
		$this->db->setQuery($query);
		/**
		 *
		 * @var object|FALSE $result
		 */
		$result = $this->db->loadResult();
		if (!$result)
		{
			/**
			 * No user found
			 */
			return FALSE;
		}
		elseif ($result->ban = '1')
		{
			/**
			 * User is banned
			 */
			return FALSE;
		}
		elseif ($result->active != '1')
		{
			/**
			 * User is not active
			 */
			return FALSE;
		}

		return password_verify($credentials['password'], $result->password);
	}

	private function checkUser($credentials)
	{
		if ($this->db instanceof \JDatabaseDriver)
		{
			$this->getDbo();
		}

		if ($this->checkPassword($credentials) == FALSE)
		{
			/**
			 * Password doesn't match but we don't say it out loud
			 */
			$this->response->status = \Joomla\CMS\Authentication\Authentication::STATUS_FAILURE;
			$this->response->error_message = 'User does not exist';
			return FALSE;
		}
		$this->pH7userID = \Joomla\CMS\User\UserHelper::getUserId($credentials['username']);
		if ($this->pH7userID !== '0')
		{
			/**
			 * If not a new user then we simply accept when password is valid !
			 */
			$this->response->email = \Joomla\CMS\User\User::getInstance($this->pH7userID)->email;
			$this->response->status = \Joomla\CMS\Authentication\Authentication::STATUS_SUCCESS;
			return TRUE;
		}

		$this->response->email = $this->getPassword($credentials);
		$this->response->status = \Joomla\CMS\Authentication\Authentication::STATUS_SUCCESS;
		return TRUE;
	}

	private function getPassword($credentials)
	{
		if ($this->db instanceof \JDatabaseDriver)
		{
			$this->getDbo();
		}

		/**
		 * Get a query referenced to pH7CMS members table and lookup username against provider credentials
		 * @var JDatabaseQuery $query
		 */
		$query = $this->db->getQuery(true)
		->select('username')
		->from($this->ph7prefix.'members')
		->where('username='.$db->quote($credentials['username']));
		$this->db->setQuery($query);
		/**
		 *
		 * @var object|FALSE $result
		 */
		$result = $this->db->loadResult();
		if (!$result)
		{
			/**
			 * No user found
			 */
			return FALSE;
		}
		else
		{
			return $result->email;
		}
	}

	/**
	 * Invoked when before a user modification is saved
	 * @param \Joomla\CMS\User\User $old_user
	 * @param boolean $isnew
	 * @param \Joomla\CMS\User\User $new_user
	 */
	public function onUserBeforeSave ($old_user, $isnew, $new_user)
	{

	}
	public function onUserAuthenticate($credentials, $options, \Joomla\CMS\Authentication\AuthenticationResponse &$response)
	{
		/**
		 * Don't allow usage on the administrator side
		 * For security reason
		 */
		if (\Joomla\CMS\Factory::getApplication()->isClient('administrator'))
		{
			return;
		}
		if ($this->checkUser($credentials) == TRUE)
		{
			$response = $this->response;
		}
		else
		{
			return;
		}
	}
}