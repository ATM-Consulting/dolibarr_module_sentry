<?php
/* Copyright (C) 2023		Laurent Destailleur			<eldy@users.sourceforge.net>
 * Copyright (C) 2025		SuperAdmin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * \file    sentry/class/actions_sentry.class.php
 * \ingroup sentry
 * \brief   Example hook overload.
 *
 */

require_once DOL_DOCUMENT_ROOT.'/core/class/commonhookactions.class.php';

/**
 * Class ActionsSentry
 */
class ActionsSentry extends CommonHookActions
{
	/**
	 * @var DoliDB Database handler.
	 */
	public $db;

	/**
	 * @var string Error code (or message)
	 */
	public $error = '';

	/**
	 * @var string[] Errors
	 */
	public $errors = [];


	/**
	 * @var mixed[] Hook results. Propagated to $hookmanager->resArray for later reuse
	 */
	public $results = [];

	/**
	 * @var ?string String displayed by executeHook() immediately after return
	 */
	public $resprints;

	/**
	 * @var int		Priority of hook (50 is used if value is not defined)
	 */
	public $priority;


	/**
	 * Constructor
	 *
	 *  @param	DoliDB	$db      Database handler
	 */
	public function __construct($db)
	{
		$this->db = $db;
	}


	/**
	 * @param $parameters
	 * @param $object
	 * @param $action
	 * @param $hookmanager
	 * @return int
	 */
	public function addHtmlHeader(&$parameters, &$object, &$action, $hookmanager)
	{
		global $user;

		if (!empty($_SERVER['SENTRY_ENABLED'])) {
			try {
				ob_start();
				require_once __DIR__ . '/../head.phtml';
				$html = ob_get_clean();
			} catch (Throwable $t) {
				$html = '<script nonce="'.getNonce().'">alert("Sentry: '.addslashes($t->getMessage()).'");</script>'."\n";
			}

			$this->resprints .= $html;
		}

		return 0;
	}

	protected function getUrl(string $file): string
	{
		return dol_buildpath('sentry/'.$file, 1).'?v=7910';
	}
}
