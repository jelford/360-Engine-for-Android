/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * src/com/vodafone360/people/VODAFONE.LICENSE.txt or
 * http://github.com/360/360-Engine-for-Android
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each file and
 * include the License file at src/com/vodafone360/people/VODAFONE.LICENSE.txt.
 * If applicable, add the following below this CDDL HEADER, with the fields
 * enclosed by brackets "[]" replaced with your own identifying information:
 * Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2010 Vodafone Sales & Services Ltd.  All rights reserved.
 * Use is subject to license terms.
 */

package com.vodafone360.people.database.tables;

import java.util.ArrayList;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;

import com.vodafone360.people.database.DatabaseHelper;
import com.vodafone360.people.database.SQLKeys;

import com.vodafone360.people.datatypes.ContactSummary.OnlineStatus;
import com.vodafone360.people.engine.presence.NetworkPresence;
import com.vodafone360.people.engine.presence.User;
import com.vodafone360.people.utils.CloseUtils;
import com.vodafone360.people.utils.LogUtils;
import com.vodafone360.people.utils.StringBufferPool;

/**
 * PresenceTable... The table for storing the presence states of contacts.
 * 
 * @throws SQLException is thrown when request to create a table fails with an
 *             SQLException
 * @throws NullPointerException if the passed in database instance is null
 */
public abstract class PresenceTable {

    /***
     * The name of the table as it appears in the database.
     */
    public static final String TABLE_NAME = "Presence"; // it is used in the

    // tests

    /**
     * The return types for the add/update method: if a new record was added.
     */
    public static final int USER_ADDED = 0;

    /**
     * The return types for the add/update method: if an existing record was
     * updated.
     */
    public static final int USER_UPDATED = 1;

    /**
     * The return types for the add/update method: if an error happened and
     * prevented the record from being added or updated.
     */
    public static final int USER_NOTADDED = 2;

    /**
     * An enumeration of all the field names in the database, containing ID,
     * LOCAL_CONTACT_ID, USER_ID, NETWORK_ID, NETWORK_STATUS.
     */
    private static enum Field {
        /**
         * The primary key.
         */
        ID("id"),
        /**
         * The internal representation of the serverId for this account.
         */
        LOCAL_CONTACT_ID("LocalContactId"),
        /**
         * This is contact list id: gmail, facebook, nowplus or other account,
         * STRING.
         */
        USER_ID("ImAddress"),
        /**
         * The SocialNetwork id, INT.
         */
        NETWORK_ID("NetworkId"),
        /**
         * The presence status id, INT.
         */
        NETWORK_STATUS("Status");

        /**
         * The name of the field as it appears in the database.
         */
        private String mField;

        /**
         * Constructor.
         * 
         * @param field - Field name
         */
        private Field(String field) {
            mField = field;
        }

        /*
         * This implementation returns the field name. (non-Javadoc)
         * @see java.lang.Enum#toString()
         */
        public String toString() {
            return mField;
        }
    }

    /**
     * The constants for column indexes in the table: LocalContactId
     */
    private static final int LOCAL_CONTACT_ID = 1;

    /**
     * The constants for column indexes in the table: ImAddress
     */
    private static final int USER_ID = 2;

    /**
     * The constants for column indexes in the table: NetworkId
     */
    private static final int NETWORK_ID = 3;

    /**
     * The constants for column indexes in the table: Status
     */
    private static final int NETWORK_STATUS = 4;

    /**
     * The default message for the NullPointerException caused by the null
     * instance of database passed into PresenceTable methods.
     */
    private static final String DEFAULT_ERROR_MESSAGE = "PresenceTable: the passed in database is null!";

    /**
     * This method creates the PresenceTable.
     * 
     * @param writableDb - the writable database
     * @throws SQLException is thrown when request to create a table fails with
     *             an SQLException
     * @throws NullPointerException if the passed in database instance is null
     */
    public static void create(SQLiteDatabase writableDb) throws SQLException, NullPointerException {
        DatabaseHelper.trace(true, "PresenceTable.create()");
        if (writableDb == null) {
            throw new NullPointerException(DEFAULT_ERROR_MESSAGE);
        }
        String createSql = "CREATE TABLE IF NOT EXISTS " + DatabaseHelper.DATABASE_PRESENCE + "." + TABLE_NAME + " (" + Field.ID
                + " INTEGER PRIMARY KEY AUTOINCREMENT, " + Field.LOCAL_CONTACT_ID + " LONG, "
                + Field.USER_ID + " STRING, " + Field.NETWORK_ID + " INT, " + Field.NETWORK_STATUS
                + " INT);";
        writableDb.execSQL(createSql);
    }

    /**
     * This method updates the user with the information from the User wrapper.
     * 
     * @param user2Update - User info to update
     * @param writableDatabase - writable database
     * @return USER_ADDED if no user with user id like the one in user2Update
     *         payload "status.getUserId()" ever existed in this table,
     *         USER_UPDATED if the user already existed in the table and has
     *         been successfully added, USER_NOT_ADDED - if user was not added.
     * @throws SQLException if the database layer throws this exception.
     * @throws NullPointerException if the passed in database instance is null.
     */
    public static int updateUser(User user2Update, SQLiteDatabase writableDatabase)
            throws SQLException, NullPointerException {
        int ret = USER_NOTADDED;
        if (writableDatabase == null) {
            throw new NullPointerException(DEFAULT_ERROR_MESSAGE);
        }
        if (user2Update != null) {
            ArrayList<NetworkPresence> statusesOnNetworks = user2Update.getPayload();
            if (!statusesOnNetworks.isEmpty()) {
                ContentValues values = new ContentValues();
                StringBuffer where = null;
                for (NetworkPresence status : statusesOnNetworks) {
                    values.put(Field.LOCAL_CONTACT_ID.toString(), user2Update.getLocalContactId());
                    values.put(Field.USER_ID.toString(), status.getUserId());
                    values.put(Field.NETWORK_ID.toString(), status.getNetworkId());
                    values.put(Field.NETWORK_STATUS.toString(), status.getOnlineStatusId());

                    where = StringBufferPool.getStringBuffer(Field.LOCAL_CONTACT_ID.toString());
                    
                    where.append(SQLKeys.EQUALS).append(user2Update.getLocalContactId()).
                    append(SQLKeys.AND).append(Field.NETWORK_ID).append(SQLKeys.EQUALS).append(status.getNetworkId());
                    
                    int numberOfAffectedRows = writableDatabase.update(TABLE_NAME, values, StringBufferPool.toStringThenRelease(where),
                            null);
                    if (numberOfAffectedRows == 0) {
                        writableDatabase.insertOrThrow(TABLE_NAME, null, values);
                        ret = USER_ADDED;
                    } else {
                        if (ret == USER_NOTADDED) {
                            ret = USER_UPDATED;
                        }
                    }
                    values.clear();
                }
            }
        }
        return ret;
    }

    /**
     * This method returns user/me profile presence state.
     * 
     * @param localContactId - me profile localContactId
     * @param readableDatabase - the database to read from
     * @return user/me profile presence state wrapped in "User" wrapper class,
     *         or NULL if the specified localContactId doesn't exist
     * @throws SQLException if the database layer throws this exception.
     * @throws NullPointerException if the passed in database instance is null.
     */
    public static User getUserPresenceByLocaContactId(long localContactId,
            SQLiteDatabase readableDatabase) throws SQLException, NullPointerException {
        if (readableDatabase == null) {
            throw new NullPointerException(DEFAULT_ERROR_MESSAGE);
        }
        User user = null;
        if (localContactId < 0) {
            LogUtils.logE("PresenceTable.getMeProfilePresenceById(): "
                    + "#localContactId# parameter is -1 ");
            return user;
        }
        Cursor c = null;
        try {
            c = readableDatabase.rawQuery("SELECT * FROM " + TABLE_NAME + " WHERE "
                    + Field.LOCAL_CONTACT_ID + "=" + localContactId, null);

            ArrayList<NetworkPresence> networkPresence = new ArrayList<NetworkPresence>();
            user = new User();
            int onlineStatus = OnlineStatus.OFFLINE.ordinal(); // i.e. 0
            while (c.moveToNext()) {
                user.setLocalContactId(c.getLong(LOCAL_CONTACT_ID));
                String userId = c.getString(USER_ID);
                int networkId = c.getInt(NETWORK_ID);
                int statusId = c.getInt(NETWORK_STATUS);
                if (statusId > onlineStatus) {
                    onlineStatus = statusId;
                }
                networkPresence.add(new NetworkPresence(userId, networkId, statusId));
            }
            if (!networkPresence.isEmpty()) {
                user.setOverallOnline(onlineStatus);
                user.setPayload(networkPresence);
            }
            // this finally part should always run, while the exception is still
            // thrown
        } finally {
            CloseUtils.close(c);
            c = null;
        }
        return user;
    }

    /**
     * The method cleans the presence table: deletes all the rows.
     * 
     * @param writableDatabase - database to write to.
     * @return the number of rows affected if a whereClause is passed in, 0
     *         otherwise.
     * @throws NullPointerException if the passed in database instance is null.
     */
    public static int setAllUsersOffline(SQLiteDatabase writableDatabase)
            throws NullPointerException {
        if (writableDatabase == null) {
            throw new NullPointerException(DEFAULT_ERROR_MESSAGE);
        }
        // To remove all rows and get a count pass "1" as the whereClause
        return writableDatabase.delete(TABLE_NAME, "1", null);
    }

    /**
     * The method cleans the presence table: deletes all the rows, except for
     * the given user localContactId ("Me Profile" localContactId)
     * 
     * @param localContactIdOfMe - the localContactId of the user (long), whose
     *            info should not be deleted
     * @param writableDatabase - database to write to.
     * @return the number of rows affected if a whereClause is passed in, 0
     *         otherwise.
     * @throws NullPointerException if the passed in database instance is null.
     */
    public static int setAllUsersOfflineExceptForMe(long localContactIdOfMe,
            SQLiteDatabase writableDatabase) throws NullPointerException {
        if (writableDatabase == null) {
            throw new NullPointerException(DEFAULT_ERROR_MESSAGE);
        }
        return writableDatabase.delete(TABLE_NAME, Field.LOCAL_CONTACT_ID + " != "
                + localContactIdOfMe, null);
    }
}
